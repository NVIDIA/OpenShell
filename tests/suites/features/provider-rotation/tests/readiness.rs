// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider changes acknowledged through a sandbox HTTPS request path.
//!
//! Attach, update, and detach wait for confirmation of their exact saved
//! changes. Clients launched after attach and update keep their own static
//! references. The first request from the client launched after the update
//! uses the new credential, and detach revokes both retained references and
//! removes the credential from later launches.
//!
//! Ported from the `provider_readiness` e2e test, which ran the servers in
//! containers on the e2e network and swapped the supervisor image to trust
//! their CA. Here they run on the test host and the environment's additional
//! CA signs them.

use std::time::Duration;

use host_server_support::TEST_HOST;
use provider_rotation::{
    Backends, Counts, Credential, READINESS_TIMEOUT_SECONDS, TOKEN_ENV, check, cli_json, keys,
    probe, probe_disallowed_binary,
};
use serde_json::{Value, json};
use testkit::{CliChild, Context, Error, PYTHON_BINARIES, Result, Sandbox};

const READY: &str = "rotation-client-ready";
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// A client that checks it got an issued reference, prints [`READY`], and
/// then answers probes (see [`probe`]). Its source holds no key.
const CLIENT: &str = r"
import json, os, pathlib, re, ssl, sys, time, urllib.error, urllib.request

config = json.loads(sys.argv[1])
key = config['key']
token = os.environ.get(key, '')
if not re.fullmatch(r'openshell:resolve:env:v[1-9][0-9]*_' + key, token):
    print('client did not receive a revision-scoped reference', flush=True)
    sys.exit(64)
client = sys.argv[2]
pid = os.getpid()
control = pathlib.Path('/sandbox/rotation-probe-' + client)
result = pathlib.Path('/sandbox/rotation-result-' + client)

def probe(phase):
    host, port, path = config['host'], config['port'], '/v1/chat/completions'
    target = phase[:-8] if phase.endswith('_control') else phase
    if target == 'wrong_host':
        host = config['other_host']
    elif target == 'wrong_port':
        port = config['other_port']
    elif target == 'wrong_path':
        path = '/outside'
    url = 'https://%s:%s%s' % (host, port, path)
    response = {'phase': phase, 'pid': pid, 'same_reference': os.environ.get(key) == token,
                'ok': False, 'status': 0, 'backend_phase': -1}
    try:
        context = ssl.create_default_context()
        if phase == 'untrusted_ca':
            # An empty trust store proves this client does verify TLS.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        headers = {'Content-Type': 'application/json'}
        if not phase.endswith('_control'):
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(url, data=b'{}', headers=headers)
        try:
            reply = urllib.request.urlopen(request, context=context, timeout=5)
        except urllib.error.HTTPError as error:
            # The server's 401 body proves the endpoint is reachable.
            reply = error
        with reply:
            body = json.loads(reply.read(1024))
            response['ok'] = body.get('authorized') is True
            response['status'] = reply.status
            response['backend_phase'] = body.get('phase', -1)
    except Exception as error:
        # HTTP and TLS errors can embed headers; report only type names.
        response['error_kind'] = type(error).__name__
        response['reason_kind'] = type(getattr(error, 'reason', None)).__name__
    return response

print('rotation-client-ready', flush=True)
deadline = time.monotonic() + 600
while time.monotonic() < deadline:
    if control.exists():
        phase = control.read_text().strip()
        control.unlink()
        temporary = result.with_suffix('.tmp')
        temporary.write_text(json.dumps(probe(phase)))
        temporary.replace(result)
    time.sleep(0.05)
";

/// Attach, a single update, and detach each wait for acknowledgment. Two
/// clients, launched after attach and after the update, keep running
/// throughout, and detach revokes both of their references.
#[testkit::test]
async fn acknowledged_changes_reach_fresh_clients_and_detach_revokes_retained_references(
    cx: &mut Context,
) -> testkit::Result {
    let keys = keys();
    let backends = Backends::start(Credential::Bearer, &keys).await?;
    let provider = cx.name("ready");
    let provider_type = cx
        .import_profile(&profile(&provider, backends.port()))
        .await?;
    cx.create_provider(&provider, &provider_type, &[(TOKEN_ENV, &keys[0])])
        .await?;
    let sandbox = cx
        .sandbox("ready")
        .image(testkit::python_image())
        .policy(backends.policy()?)
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    let config = json!({"key": TOKEN_ENV, "host": TEST_HOST, "other_host": backends.other_host(),
        "port": backends.port(), "other_port": backends.other_port()})
    .to_string();
    future_environment(&sandbox, false).await?;

    let output = cli_json(
        cx,
        &[],
        &[
            "sandbox",
            "provider",
            "attach",
            sandbox.name(),
            &provider,
            "-o",
            "json",
        ],
        &keys,
    )
    .await?;
    let attach = Receipt::capture(&output, &sandbox, &provider, "attach")?;
    attach.wait(cx, &sandbox, &provider, "ready", &keys).await?;
    future_environment(&sandbox, true).await?;
    // Client A starts only after the launch environment is acknowledged,
    // and keeps that reference until the sandbox is deleted.
    let _client_a = start_client(cx, &sandbox, &config, "a").await?;
    let initial = probe(&sandbox, "a", "initial", None).await?;
    let pid_a = pid(&initial)?;
    check(&initial, pid_a, true, Some(0))?;
    backends.ensure_distinct_hosts()?;
    let before = backends.counts();
    testkit::ensure!(
        before.total == 1 && before.accepted[0] == 1,
        "the first request wasn't the only one accepted: {before:?}"
    );
    for phase in [
        "wrong_host_control",
        "wrong_port_control",
        "wrong_path_control",
    ] {
        let control = probe(&sandbox, "a", phase, None).await?;
        check(&control, pid_a, false, None)?;
        testkit::ensure!(
            control["status"] == 401 && control["backend_phase"] == 0,
            "{phase} without a credential didn't reach the server: {control}"
        );
    }
    let before = backends.counts();
    testkit::ensure!(
        before.total == 4 && before.rejected == 3 && before.accepted == [1, 0],
        "the requests without a credential weren't counted as rejected: {before:?}"
    );
    for phase in ["wrong_host", "wrong_port", "wrong_path", "untrusted_ca"] {
        check(
            &probe(&sandbox, "a", phase, None).await?,
            pid_a,
            false,
            None,
        )?;
        expect_counts(&backends, &before, phase)?;
    }
    probe_disallowed_binary(
        &sandbox,
        "Authorization: Bearer ",
        &format!(
            "https://{TEST_HOST}:{}/v1/chat/completions",
            backends.port()
        ),
        "{}",
    )
    .await?;
    expect_counts(&backends, &before, "the request from curl")?;

    backends.rotate();
    let output = cli_json(
        cx,
        &[(TOKEN_ENV, &keys[1])],
        &[
            "provider",
            "update",
            &provider,
            "--credential",
            TOKEN_ENV,
            "-o",
            "json",
        ],
        &keys,
    )
    .await?;
    let update = Receipt::capture(&output, &sandbox, &provider, "update")?;
    update.follows(&attach)?;
    // No requests happen while waiting. Client B starts after the update is
    // acknowledged, and its first request must use the new key.
    update.wait(cx, &sandbox, &provider, "ready", &keys).await?;
    future_environment(&sandbox, true).await?;
    let _client_b = start_client(cx, &sandbox, &config, "b").await?;
    let rotated_request = probe(&sandbox, "b", "rotated", None).await?;
    let pid_b = pid(&rotated_request)?;
    testkit::ensure!(pid_b != pid_a, "client B is the same process as client A");
    check(&rotated_request, pid_b, true, Some(1))?;
    let rotated = backends.counts();
    testkit::ensure!(
        rotated.total == 5 && rotated.accepted == [1, 1] && rotated.rejected == 3,
        "the servers didn't see exactly one request with the new key: {rotated:?}"
    );

    let output = cli_json(
        cx,
        &[],
        &[
            "sandbox",
            "provider",
            "detach",
            sandbox.name(),
            &provider,
            "-o",
            "json",
        ],
        &keys,
    )
    .await?;
    let detach = Receipt::capture(&output, &sandbox, &provider, "detach")?;
    detach.follows(&update)?;
    detach
        .wait(cx, &sandbox, &provider, "revoked", &keys)
        .await?;
    future_environment(&sandbox, false).await?;
    // The route stays allowed after detach, so a denial below is the
    // revoked reference, not a network failure.
    let control = probe(&sandbox, "b", "detached_control", None).await?;
    check(&control, pid_b, false, None)?;
    testkit::ensure!(
        control["status"] == 401 && control["backend_phase"] == 1,
        "the endpoint wasn't reachable without a credential after detach: {control}"
    );
    let detached = backends.counts();
    testkit::ensure!(
        detached
            == Counts {
                total: 6,
                accepted: [1, 1],
                rejected: 4,
                phase: 1,
                ..detached.clone()
            },
        "the request without a credential after detach wasn't counted as rejected: {detached:?}"
    );
    for (client, pid) in [("a", pid_a), ("b", pid_b)] {
        check(
            &probe(&sandbox, client, "detached", None).await?,
            pid,
            false,
            None,
        )?;
        expect_counts(
            &backends,
            &detached,
            &format!("client {client}'s request after detach"),
        )?;
    }
    Ok(())
}

/// A profile with one bearer credential bound to the server on `port`.
fn profile(id: &str, port: u16) -> String {
    json!({
        "id": id, "display_name": "Provider readiness test", "category": "other",
        "credentials": [{"name": "synthetic", "env_vars": [TOKEN_ENV], "required": true,
            "auth_style": "bearer", "header_name": "authorization"}],
        "endpoints": [{"host": TEST_HOST, "port": port, "path": "/v1/**", "protocol": "rest",
            "access": "full", "enforcement": "enforce"}],
        "binaries": PYTHON_BINARIES,
    })
    .to_string()
}

fn pid(response: &Value) -> Result<u64> {
    response["pid"]
        .as_u64()
        .ok_or_else(|| Error::msg(format!("probe {} reported no PID", response["phase"])))
}

fn expect_counts(backends: &Backends, expected: &Counts, what: &str) -> Result {
    let counts = backends.counts();
    testkit::ensure!(
        &counts == expected,
        "{what} reached the servers: {counts:?}, expected {expected:?}"
    );
    Ok(())
}

/// Start the client called `client` with `sandbox exec`, and wait until it
/// is ready. It runs until the returned handle is dropped.
async fn start_client(
    cx: &Context,
    sandbox: &Sandbox,
    config: &str,
    client: &str,
) -> Result<CliChild> {
    let mut child = cx.cli_spawn([
        "sandbox",
        "exec",
        "--name",
        sandbox.name(),
        "--no-tty",
        "--",
        "python3",
        "-u",
        "-c",
        CLIENT,
        config,
        client,
    ])?;
    child
        .stdout_until(START_TIMEOUT, |line| line == READY)
        .await
        .map_err(|error| error.context(format!("start client {client}")))?;
    Ok(child)
}

/// Fail unless a new process in `sandbox` gets an issued reference exactly
/// when `present` says. It reports booleans only.
async fn future_environment(sandbox: &Sandbox, present: bool) -> Result {
    let script = format!(
        "import json,os,re; key='{TOKEN_ENV}'; value=os.environ.get(key,''); \
         print(json.dumps({{'present':key in os.environ,\
         'reference':bool(re.fullmatch(r'openshell:resolve:env:v[1-9][0-9]*_'+key,value))}}))"
    );
    let result = sandbox.run_python(&script, &[]).await?.last_json()?;
    testkit::ensure!(
        result["present"] == present && result["reference"] == present,
        "a new process's credential reference didn't match the acknowledged provider state \
         (expected present={present}): {result}"
    );
    Ok(())
}

/// The receipt a provider mutation printed.
struct Receipt {
    mutation_id: String,
    receipt: Value,
}

fn single_target(body: &Value) -> Result<&Value> {
    // The provider is unique and has one attachment, so a mutation that
    // selects another sandbox or none can't pass.
    match body["targets"].as_array().map(Vec::as_slice) {
        Some([target]) => Ok(target),
        _ => Err(Error::msg(
            "the provider readiness output didn't name exactly one sandbox",
        )),
    }
}

fn nonempty<'a>(object: &'a Value, field: &str) -> Result<&'a str> {
    object[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::msg(format!("provider readiness field {field} is missing")))
}

impl Receipt {
    fn capture(body: &Value, sandbox: &Sandbox, provider: &str, kind: &str) -> Result<Self> {
        let status = single_target(body)?;
        let receipt = &status["receipt"];
        let desired = &receipt["desired"];
        let mutation_id = nonempty(body, "mutation_id")?;
        testkit::ensure!(
            receipt["mutation_id"] == mutation_id
                && receipt["provider"] == provider
                && receipt["kind"] == kind
                && desired["sandbox"] == sandbox.name()
                && status["state"] == "persisted"
                && status["wait_outcome"] == "not_requested",
            "the {kind} receipt doesn't describe the persisted change: {status}"
        );
        nonempty(receipt, "receipt_id")?;
        for field in [
            "sandbox_id",
            "attachment_epoch",
            "provider_resource_version",
            "provider_env_revision",
            "config_revision",
            "policy_hash",
        ] {
            nonempty(desired, field)?;
        }
        if kind == "detach" {
            testkit::ensure!(
                desired["provider_id"] == "" && desired["provider_resource_version"] == "0",
                "the detach receipt kept the provider: {desired}"
            );
        } else {
            nonempty(desired, "provider_id")?;
        }
        nonempty(receipt, "persisted_time")?;
        Ok(Self {
            mutation_id: mutation_id.to_string(),
            receipt: receipt.clone(),
        })
    }

    /// Fail unless this receipt is a new change to the same target as
    /// `previous`.
    fn follows(&self, previous: &Self) -> Result {
        let desired = &self.receipt["desired"];
        let preceding = &previous.receipt["desired"];
        testkit::ensure!(
            self.mutation_id != previous.mutation_id
                && self.receipt["receipt_id"] != previous.receipt["receipt_id"]
                && self.receipt["provider"] == previous.receipt["provider"]
                && self.receipt["workspace"] == previous.receipt["workspace"]
                && desired["sandbox_id"] == preceding["sandbox_id"]
                && desired["sandbox"] == preceding["sandbox"]
                && desired["provider_env_revision"] != preceding["provider_env_revision"],
            "the {} receipt isn't a distinct change to the same target: {desired} after {preceding}",
            self.receipt["kind"]
        );
        // Revisions are opaque, so only equality means anything.
        if self.receipt["kind"] == "update" {
            testkit::ensure!(
                desired["provider_id"] == preceding["provider_id"]
                    && desired["provider_resource_version"]
                        != preceding["provider_resource_version"]
                    && desired["attachment_epoch"] == preceding["attachment_epoch"],
                "the update didn't keep its attachment: {desired} after {preceding}"
            );
        }
        if self.receipt["kind"] == "detach" {
            testkit::ensure!(
                desired["attachment_epoch"] != preceding["attachment_epoch"],
                "the detach didn't replace the attachment epoch: {desired}"
            );
        }
        Ok(())
    }

    /// Wait for the receipt to complete in `expected_state`, and check the
    /// sandbox installed exactly what it asked for.
    async fn wait(
        &self,
        cx: &Context,
        sandbox: &Sandbox,
        provider: &str,
        expected_state: &str,
        keys: &[String; 2],
    ) -> Result {
        let body = cli_json(
            cx,
            &[],
            &[
                "sandbox",
                "provider",
                "status",
                sandbox.name(),
                provider,
                "--receipt",
                nonempty(&self.receipt, "receipt_id")?,
                "--wait",
                "--timeout",
                READINESS_TIMEOUT_SECONDS,
                "-o",
                "json",
            ],
            keys,
        )
        .await?;
        let status = single_target(&body)?;
        testkit::ensure!(
            body["mutation_id"] == self.mutation_id.as_str()
                && status["receipt"] == self.receipt
                && status["state"] == expected_state
                && status["reason"] == "unspecified"
                && status["wait_outcome"] == "complete",
            "the {} receipt didn't complete as {expected_state}: {status}",
            self.receipt["kind"]
        );
        let desired = &self.receipt["desired"];
        let observed = &status["observed"];
        for field in [
            "attachment_epoch",
            "provider_env_revision",
            "config_revision",
            "policy_hash",
        ] {
            testkit::ensure!(
                observed[field] == desired[field],
                "the sandbox installed {field} {}, not {}",
                observed[field],
                desired[field]
            );
        }
        for field in [
            "credentials_installed",
            "policy_active",
            "launch_environment_installed",
        ] {
            testkit::ensure!(
                observed[field] == true,
                "the receipt completed without {field}: {observed}"
            );
        }
        for field in ["session_id", "sequence", "process_instance_id"] {
            nonempty(observed, field)?;
        }
        nonempty(status, "network_instance_id")?;
        nonempty(status, "observed_time")?;
        nonempty(status, "evaluated_time")?;
        testkit::ensure!(
            observed["reason"] == "unspecified",
            "the installation wasn't acknowledged successfully: {observed}"
        );
        Ok(())
    }
}
