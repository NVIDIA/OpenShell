// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! External caller assertion rotation through a sandbox HTTPS request path.
//!
//! The sandbox's main process keeps one supervisor-issued reference and sends
//! a `tools/call` request with it whenever the test asks. After one provider
//! update, a stable placeholder resolves to the new assertion, while an
//! ordinary reference keeps the revoked one. This exercises credential
//! substitution, not an MCP session.
//!
//! Ported from the `stable_external_placeholders` e2e test, which ran the
//! servers in containers on the e2e network and swapped the supervisor image
//! to trust their CA. Here they run on the test host and the environment's
//! additional CA signs them.

use std::time::Duration;

use host_server_support::TEST_HOST;
use provider_rotation::{
    ASSERTION_HEADER, Backends, Counts, Credential, READINESS_TIMEOUT_SECONDS, TOKEN_ENV, check,
    cli_json, keys, probe, probe_disallowed_binary, tool_call,
};
use serde_json::{Value, json};
use testkit::{Context, Error, PYTHON_BINARIES, Result, Sandbox};

/// The main process's client name in [`probe`].
const CLIENT_NAME: &str = "main";
/// How long the main process has to start before it answers the first probe.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// A client that checks it got the expected kind of issued reference and
/// answers probes (see [`probe`]), or with `--once`, sends one request and
/// prints the result. Its source holds no key.
const CLIENT: &str = r"
import json, os, pathlib, re, ssl, sys, time, urllib.error, urllib.request

config = json.loads(sys.argv[1])
key = config['key']
token = os.environ.get(key, '')
pattern = r's[0-9a-f]{64}' if config['stable'] else r'v[1-9][0-9]*'
if not re.fullmatch(r'openshell:resolve:env:' + pattern + '_' + key, token):
    print('client did not receive the expected issued reference', flush=True)
    sys.exit(64)
pid = os.getpid()
control = pathlib.Path('/sandbox/rotation-probe-main')
result = pathlib.Path('/sandbox/rotation-result-main')

def probe(phase):
    host, port, path = config['host'], config['port'], '/mcp/local-hello'
    authorization = token
    target = phase[:-8] if phase.endswith('_control') else phase
    if target == 'wrong_host':
        host = config['other_host']
    elif target == 'wrong_port':
        port = config['other_port']
    elif target == 'wrong_path':
        path = '/outside'
    elif phase == 'canonical_alias':
        authorization = 'openshell:resolve:env:' + key
    url = 'https://%s:%s%s' % (host, port, path)
    response = {'phase': phase, 'pid': pid, 'same_reference': os.environ.get(key) == token,
                'ok': False, 'status': 0, 'backend_phase': -1,
                'credential_generation': 'unobserved', 'tool_call': False}
    try:
        context = ssl.create_default_context()
        if phase == 'untrusted_ca':
            # An empty trust store proves this client does verify TLS.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        headers = {'Content-Type': 'application/json'}
        if not phase.endswith('_control'):
            headers[config['header']] = authorization
        request = urllib.request.Request(url, data=json.dumps(config['payload']).encode(),
                                         headers=headers)
        try:
            reply = urllib.request.urlopen(request, context=context, timeout=5)
        except urllib.error.HTTPError as error:
            # The server's 401 body proves the endpoint is reachable.
            reply = error
        with reply:
            body = json.loads(reply.read(1024))
            attestation = body.get('fixture', {})
            response['ok'] = (attestation.get('authorized') is True
                              and body.get('result', {}).get('content') ==
                              [{'type': 'text', 'text': 'Hello rotation-proof'}])
            response['status'] = reply.status
            response['backend_phase'] = attestation.get('phase', -1)
            response['credential_generation'] = attestation.get('credential_generation', 'unobserved')
            response['tool_call'] = attestation.get('tool_call') is True
    except Exception as error:
        # HTTP and TLS errors can embed headers; report only type names.
        response['error_kind'] = type(error).__name__
        response['reason_kind'] = type(getattr(error, 'reason', None)).__name__
    return response

if len(sys.argv) > 2 and sys.argv[2] == '--once':
    print(json.dumps(probe('fresh')), flush=True)
    sys.exit(0)

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

/// With `stable_placeholder`, the main process's retained reference resolves
/// to the new assertion after one update, and detach revokes it.
#[testkit::test]
async fn stable_placeholder_follows_rotation_and_detach_revokes(
    cx: &mut Context,
) -> testkit::Result {
    assertion_rotation(cx, true).await
}

/// Without `stable_placeholder`, the main process's retained reference keeps
/// sending the revoked assertion after an update, while a new process sends
/// the new one.
#[testkit::test]
async fn ordinary_reference_keeps_revoked_assertion_after_rotation(
    cx: &mut Context,
) -> testkit::Result {
    assertion_rotation(cx, false).await
}

// One lifecycle, so no phase can replace the retained client.
#[allow(clippy::too_many_lines)]
async fn assertion_rotation(cx: &Context, stable: bool) -> Result {
    let keys = keys();
    let backends = Backends::start(Credential::Assertion, &keys).await?;
    let suffix = if stable { "stbl" } else { "ordn" };
    let provider = cx.name(suffix);
    let provider_type = cx
        .import_profile(&profile(&provider, backends.port(), stable))
        .await?;
    cx.create_provider(&provider, &provider_type, &[(TOKEN_ENV, &keys[0])])
        .await?;
    let config = json!({"key": TOKEN_ENV, "header": ASSERTION_HEADER, "payload": tool_call(),
        "host": TEST_HOST, "other_host": backends.other_host(), "port": backends.port(),
        "other_port": backends.other_port(), "stable": stable})
    .to_string();
    let sandbox = cx
        .sandbox(suffix)
        .image(testkit::python_image())
        .providers([provider.as_str()])
        .policy(backends.policy()?)
        .command(["python3", "-u", "-c", CLIENT, &config])
        .create_ready()
        .await?;

    let initial = probe(&sandbox, CLIENT_NAME, "initial", Some(START_TIMEOUT)).await?;
    let pid = pid(&initial)?;
    check_generation(&initial, pid, true, Some(0))?;
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
        let control = probe(&sandbox, CLIENT_NAME, phase, None).await?;
        check(&control, pid, false, None)?;
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
    for phase in [
        "wrong_host",
        "wrong_port",
        "wrong_path",
        "canonical_alias",
        "untrusted_ca",
    ] {
        check(
            &probe(&sandbox, CLIENT_NAME, phase, None).await?,
            pid,
            false,
            None,
        )?;
        expect_counts(&backends, &before, phase)?;
    }
    probe_disallowed_binary(
        &sandbox,
        &format!("{ASSERTION_HEADER}: "),
        &format!("https://{TEST_HOST}:{}/mcp/local-hello", backends.port()),
        &tool_call().to_string(),
    )
    .await?;
    expect_counts(&backends, &before, "the request from curl")?;

    backends.rotate();
    // The only update. --wait acknowledges the saved revision before the
    // client sends its next request.
    acknowledged_mutation(
        cx,
        &[(TOKEN_ENV, &keys[1])],
        &["provider", "update", &provider, "--credential", TOKEN_ENV],
        &sandbox,
        &provider,
        "update",
        &keys,
    )
    .await?;
    // The next request must send B with the opt-in; the ordinary reference
    // still resolves to A.
    let retained = probe(&sandbox, CLIENT_NAME, "rotated", None).await?;
    check_generation(&retained, pid, stable, stable.then_some(1))?;
    if !stable {
        testkit::ensure!(
            retained["status"] == 401
                && retained["backend_phase"] == 1
                && retained["credential_generation"] == "A"
                && retained["tool_call"] == true,
            "the ordinary retained reference didn't send the revoked assertion A: {retained}"
        );
    }
    let rejected = if stable { 3 } else { 4 };
    let rotated = backends.counts();
    let expected = Counts {
        phase: 1,
        total: 5,
        accepted: if stable { [1, 1] } else { [1, 0] },
        rejected,
        received: if stable { [1, 1] } else { [2, 0] },
        missing: 3,
        unknown: 0,
        invalid_tool_calls: 0,
    };
    testkit::ensure!(
        rotated == expected,
        "after the update the servers saw {rotated:?}, expected {expected:?}"
    );

    // A new process uses B in both modes. It leaves the main process alone.
    let fresh = sandbox
        .run_python(CLIENT, &[&config, "--once"])
        .await?
        .last_json()?;
    let fresh_pid = self::pid(&fresh)?;
    testkit::ensure!(
        fresh_pid != pid && fresh["same_reference"] == true,
        "the new process isn't separate from the main process: {fresh}"
    );
    check_generation(&fresh, fresh_pid, true, Some(1))?;
    let refreshed = backends.counts();
    let expected = Counts {
        total: 6,
        accepted: if stable { [1, 2] } else { [1, 1] },
        received: if stable { [1, 2] } else { [2, 1] },
        ..expected
    };
    testkit::ensure!(
        refreshed == expected,
        "the new process's request didn't send assertion B: the servers saw {refreshed:?}, \
         expected {expected:?}"
    );

    acknowledged_mutation(
        cx,
        &[],
        &["sandbox", "provider", "detach", sandbox.name(), &provider],
        &sandbox,
        &provider,
        "detach",
        &keys,
    )
    .await?;
    // The route stays allowed after detach, so a denial below is the
    // revoked reference, not a network failure.
    let control = probe(&sandbox, CLIENT_NAME, "detached_control", None).await?;
    check(&control, pid, false, None)?;
    testkit::ensure!(
        control["status"] == 401 && control["backend_phase"] == 1,
        "the endpoint wasn't reachable without a credential after detach: {control}"
    );
    let detached = backends.counts();
    let expected = Counts {
        total: 7,
        rejected: rejected + 1,
        missing: 4,
        ..expected
    };
    testkit::ensure!(
        detached == expected,
        "after detach the servers saw {detached:?}, expected {expected:?}"
    );
    check(
        &probe(&sandbox, CLIENT_NAME, "detached", None).await?,
        pid,
        false,
        None,
    )?;
    expect_counts(&backends, &detached, "the request after detach")
}

/// A profile with one header credential bound to the server on `port`,
/// opting in to a stable placeholder when `stable` says. Without the
/// opt-in, it behaves as an existing static credential profile.
fn profile(id: &str, port: u16, stable: bool) -> String {
    let mut credential = json!({"name": "synthetic_assertion", "env_vars": [TOKEN_ENV],
        "required": true, "auth_style": "header", "header_name": ASSERTION_HEADER});
    if stable {
        credential["stable_placeholder"] = json!(true);
    }
    json!({
        "id": id, "display_name": "External caller assertion test", "category": "other",
        "credentials": [credential],
        "endpoints": [{"host": TEST_HOST, "port": port, "path": "/mcp/**", "protocol": "rest",
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

/// [`check`], and with `backend_phase`, the server also saw that phase's
/// assertion in a valid tool call.
fn check_generation(
    response: &Value,
    pid: u64,
    success: bool,
    backend_phase: Option<u64>,
) -> Result {
    check(response, pid, success, backend_phase)?;
    if let Some(phase) = backend_phase {
        let generation = if phase == 0 { "A" } else { "B" };
        testkit::ensure!(
            response["credential_generation"] == generation && response["tool_call"] == true,
            "probe {} didn't send assertion {generation} in a tool call: credential_generation={}, \
             tool_call={}",
            response["phase"],
            response["credential_generation"],
            response["tool_call"]
        );
    }
    Ok(())
}

fn expect_counts(backends: &Backends, expected: &Counts, what: &str) -> Result {
    let counts = backends.counts();
    testkit::ensure!(
        &counts == expected,
        "{what} reached the servers: {counts:?}, expected {expected:?}"
    );
    Ok(())
}

/// Run a provider mutation with `--wait` and check it was acknowledged for
/// `sandbox` with exactly what it asked for.
async fn acknowledged_mutation(
    cx: &Context,
    env: &[(&str, &str)],
    args: &[&str],
    sandbox: &Sandbox,
    provider: &str,
    kind: &str,
    keys: &[String; 2],
) -> Result {
    let mut args = args.to_vec();
    args.extend([
        "--wait",
        "--timeout",
        READINESS_TIMEOUT_SECONDS,
        "-o",
        "json",
    ]);
    let body = cli_json(cx, env, &args, keys).await?;
    let Some([status]) = body["targets"].as_array().map(Vec::as_slice) else {
        return Err(Error::msg(format!(
            "the {kind} wasn't acknowledged for exactly one sandbox: {body}"
        )));
    };
    let receipt = &status["receipt"];
    let desired = &receipt["desired"];
    let observed = &status["observed"];
    let expected = if kind == "detach" { "revoked" } else { "ready" };
    testkit::ensure!(
        body["mutation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
            && receipt["mutation_id"] == body["mutation_id"]
            && receipt["provider"] == provider
            && receipt["kind"] == kind
            && desired["sandbox"] == sandbox.name()
            && status["state"] == expected
            && status["wait_outcome"] == "complete"
            && status["reason"] == "unspecified"
            && observed["reason"] == "unspecified",
        "the {kind} wasn't acknowledged as {expected} for {}: {status}",
        sandbox.name()
    );
    for field in [
        "attachment_epoch",
        "provider_env_revision",
        "config_revision",
        "policy_hash",
    ] {
        testkit::ensure!(
            desired[field]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                && observed[field] == desired[field],
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
            "the {kind} was acknowledged without {field}: {observed}"
        );
    }
    Ok(())
}
