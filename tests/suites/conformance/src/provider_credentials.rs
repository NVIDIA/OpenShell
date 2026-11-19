// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider credentials: where the supervisor substitutes them in requests,
//! what the Google Cloud metadata server in the sandbox hands out, and that
//! the gateway neither stores them in the sandbox spec nor accepts an
//! unknown provider.
//!
//! Ported from `e2e/python/test_sandbox_providers.py`. Its other cases have
//! Rust coverage already; `PLAN-kw23.md` on the porting branch maps them.
//! The upstream server runs on the test host ([`host_server_support`]), so
//! the placement tests require sandboxes to reach it as
//! `host.openshell.internal`.

use host_server_support::{HttpRecorder, Request};
use testkit::policy::{self, Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{Context, Error, GrpcCode, PYTHON_BINARIES, Result, ResultExt as _};

use crate::support::python_sandbox;

const TEST_HOST: &str = "host.openshell.internal";
const TOKEN_ENV: &str = "E2E_PLACEMENT_TOKEN";
const TEST_SECRET: &str = "synthetic-placement-secret";
/// The built-in profiles these tests need. A gateway starts without profiles,
/// so each test imports the one it uses.
const GOOGLE_CLOUD_PROFILE: &str = include_str!("../../../../providers/google-cloud.yaml");
const CLAUDE_CODE_PROFILE: &str = include_str!("../../../../providers/claude-code.yaml");
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// Sends the provider's token from `argv[2]`'s placement to `TEST_HOST` on
/// the port in `argv[1]`: first in three places the profile doesn't name
/// (a query parameter, another header, the path), then in a form body, then
/// in the place the profile names. Prints one `<status> <body>` line each.
const PLACEMENT_CLIENT: &str = r#"
import os, sys, urllib.error, urllib.parse, urllib.request
port, placement = sys.argv[1], sys.argv[2]
token = os.environ["E2E_PLACEMENT_TOKEN"]
root = f"http://host.openshell.internal:{port}"
quoted = urllib.parse.quote(token, safe="")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
requests = [
    urllib.request.Request(root + "/search?" + urllib.parse.urlencode({"q": "rust", "probe": token})),
    urllib.request.Request(root + "/search", headers={"X-Other-Credential": token}),
    urllib.request.Request(root + f"/{quoted}/search"),
    urllib.request.Request(root + "/search", data=urllib.parse.urlencode({"token": token}).encode(),
                           headers={"Content-Type": "application/x-www-form-urlencoded"}),
]
if placement == "query":
    requests.append(urllib.request.Request(root + "/search?" + urllib.parse.urlencode({"q": "rust", "api_key": token})))
else:
    requests.append(urllib.request.Request(root + "/search?q=rust", headers={"Authorization": f"token {token}"}))
for request in requests:
    try:
        with opener.open(request, timeout=30) as response:
            print(response.status, response.read().decode().replace("\n", " "))
    except urllib.error.HTTPError as error:
        print(error.code, error.read().decode().replace("\n", " "))
"#;

/// A credential the profile places in the Authorization header is refused,
/// not substituted, when the workload puts it in a query parameter, another
/// header or the path, so an upstream that reflects requests can't reveal
/// it. The endpoint's opt-in body rewriting and the Authorization header
/// get the real value.
#[testkit::test]
async fn header_credential_is_refused_in_other_request_locations(
    cx: &mut Context,
) -> testkit::Result {
    let upstream = expect_placement(cx, "phdr", "authorization").await?;
    let valid = &upstream[1];
    testkit::ensure!(
        valid
            .head
            .to_lowercase()
            .contains(&format!("authorization: token {TEST_SECRET}")),
        "the Authorization header didn't reach upstream with the credential:\n{}",
        valid.head
    );
    Ok(())
}

/// The same, for a credential the profile places in a query parameter: only
/// that parameter gets the real value.
#[testkit::test]
async fn query_credential_is_refused_in_other_request_locations(
    cx: &mut Context,
) -> testkit::Result {
    let upstream = expect_placement(cx, "pqry", "query").await?;
    let valid = &upstream[1];
    let request_line = valid.head.lines().next().unwrap_or_default();
    testkit::ensure!(
        request_line.contains(&format!("api_key={TEST_SECRET}")),
        "the api_key parameter didn't reach upstream with the credential: {request_line}"
    );
    Ok(())
}

/// Runs [`PLACEMENT_CLIENT`] for `placement` and checks what every placement
/// shares: the three reflective requests get a 403 naming the mismatch,
/// without the secret, and never reach upstream; the form body and the
/// valid request do. Returns those two upstream requests.
async fn expect_placement(cx: &Context, suffix: &str, placement: &str) -> Result<Vec<Request>> {
    let server = HttpRecorder::start("ok").await?;
    let credential = match placement {
        "query" => "    auth_style: query\n    query_param: api_key\n",
        _ => "    auth_style: bearer\n    header_name: authorization\n",
    };
    let provider = cx.name(suffix);
    let profile = format!(
        "id: {provider}
display_name: E2E Credential Placement
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
{credential}endpoints:
  - host: {TEST_HOST}
    port: {port}
    protocol: rest
    access: full
    request_body_credential_rewrite: true
binaries:
{binaries}",
        port = server.port,
        binaries = binaries_yaml(),
    );
    cx.install_provider(&provider, &profile, &[(TOKEN_ENV, TEST_SECRET)])
        .await?;
    let sandbox = python_sandbox(cx, suffix, policy::base(), &[&provider]).await?;

    let output = sandbox
        .exec([
            "python3",
            "-c",
            PLACEMENT_CLIENT,
            &server.port.to_string(),
            placement,
        ])
        .await?
        .success()
        .context("run the placement client in the sandbox")?;
    let responses: Vec<&str> = output.stdout.lines().collect();
    testkit::ensure!(
        responses.len() == 5,
        "expected five responses; got:\n{}",
        output.stdout
    );
    for (location, response) in ["query", "other header", "path"].iter().zip(&responses) {
        testkit::ensure!(
            response.starts_with("403 ")
                && response.contains("credential_placement_mismatch")
                && !response.contains(TEST_SECRET),
            "the credential in the {location} got {response:?}; expected a 403 placement mismatch without the secret"
        );
    }
    for response in &responses[3..] {
        testkit::ensure!(
            response.starts_with("200 "),
            "expected the body rewrite and the valid placement to succeed:\n{}",
            output.stdout
        );
    }

    let upstream = server.wait_for_requests(2).await?;
    testkit::ensure!(
        upstream.len() == 2,
        "expected only the body rewrite and the valid request upstream; got {}:\n{upstream:#?}",
        upstream.len()
    );
    testkit::ensure!(
        upstream[0].body == format!("token={TEST_SECRET}"),
        "the opt-in body rewrite didn't substitute the credential: {:?}",
        upstream[0].body
    );
    Ok(upstream)
}

/// Fetches the Google Cloud metadata server named by `GCE_METADATA_HOST`
/// the way Google's SDKs do, and prints what it returned as JSON.
const METADATA_CLIENT: &str = r#"
import json, os, urllib.error, urllib.request
host = os.environ["GCE_METADATA_HOST"]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(path):
    request = urllib.request.Request(f"http://{host}/computeMetadata/v1/{path}", headers={"Metadata-Flavor": "Google"})
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()
print(json.dumps({
    "metadata_host": host,
    "metadata_ip": os.environ.get("GCE_METADATA_IP"),
    "project": get("project/project-id"),
    "email": get("instance/service-accounts/default/email"),
    "token": get("instance/service-accounts/default/token"),
}))
"#;

/// The metadata server in the sandbox serves a Google Cloud provider's
/// project and service account, and an access token that is a placeholder
/// for the credential, when a policy binds the provider. Without a binding
/// it withholds the token.
#[testkit::test]
async fn google_metadata_serves_placeholder_token(cx: &mut Context) -> testkit::Result {
    const PROJECT: &str = "metadata-test-project";
    const EMAIL: &str = "sdk@metadata-test-project.iam.gserviceaccount.com";
    const SECRET: &str = "gcp-metadata-real-secret";
    const KEY: &str = "GCP_ADC_ACCESS_TOKEN";

    let provider = cx.name("gcp");
    let provider_type = cx.import_profile(GOOGLE_CLOUD_PROFILE).await?;
    cx.create_provider_with_config(
        &provider,
        &provider_type,
        &[(KEY, SECRET)],
        &[("project_id", PROJECT), ("service_account_email", EMAIL)],
    )
    .await?;

    let mut bound = policy::base();
    policy::allow(
        &mut bound,
        "gcp_api",
        "storage.googleapis.com",
        443,
        PYTHON_BINARIES,
    )
    .rest(Access::Full)
    .credential_binding(&provider);
    let metadata = fetch_metadata(cx, "gcpb", bound, &provider).await?;
    let field = |name: &str| metadata[name].clone();
    testkit::ensure!(
        field("metadata_host") == "127.0.0.1:8174" && field("metadata_ip") == "127.0.0.1:8174",
        "GCE_METADATA_HOST and GCE_METADATA_IP should both name the sandbox's metadata server: {metadata}"
    );
    testkit::ensure!(
        field("project") == serde_json::json!([200, PROJECT])
            && field("email") == serde_json::json!([200, EMAIL]),
        "unexpected project or service account: {metadata}"
    );
    testkit::ensure!(
        !metadata.to_string().contains(SECRET),
        "the metadata server revealed the credential: {metadata}"
    );
    let token = field("token");
    testkit::ensure!(token[0] == 200, "the token request failed: {metadata}");
    let token: serde_json::Value = serde_json::from_str(token[1].as_str().unwrap_or_default())
        .context("parse the token response")?;
    let access_token = token["access_token"].as_str().unwrap_or_default();
    testkit::ensure!(
        is_placeholder_for(access_token, KEY) && token["expires_in"].as_u64().is_some(),
        "the token response isn't a placeholder with an expiry: {token}"
    );

    let unbound = fetch_metadata(cx, "gcpf", policy::base(), &provider).await?;
    testkit::ensure!(
        unbound["token"][0] == 503 && !unbound.to_string().contains(SECRET),
        "without a policy binding the token should be withheld with 503: {unbound}"
    );
    Ok(())
}

async fn fetch_metadata(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    provider: &str,
) -> Result<serde_json::Value> {
    let sandbox = python_sandbox(cx, suffix, policy, &[provider]).await?;
    let output = sandbox
        .exec(["python3", "-c", METADATA_CLIENT])
        .await?
        .success()
        .context("query the metadata server in the sandbox")?;
    serde_json::from_str(output.stdout.trim()).context(format!(
        "parse the metadata client output: {}",
        output.stdout
    ))
}

/// Create refuses a sandbox that names a provider that doesn't exist, and
/// names it.
#[testkit::test]
async fn create_rejects_unknown_provider(cx: &mut Context) -> testkit::Result {
    let missing = cx.name("nope");
    let result = cx
        .sandbox("unk")
        .spec(|spec| spec.providers = vec![missing.clone()])
        .create()
        .await;
    match result {
        Ok(sandbox) => Err(Error::msg(format!(
            "the gateway accepted sandbox {} with unknown provider {missing}",
            sandbox.name()
        ))),
        Err(error) if error.grpc_code() == Some(GrpcCode::FailedPrecondition) => {
            testkit::ensure!(
                error.to_string().contains(&missing),
                "the refusal doesn't name the provider: {error}"
            );
            Ok(())
        }
        Err(error) => Err(error.context("expected a failed precondition")),
    }
}

/// The gateway resolves provider credentials when it launches the sandbox,
/// and doesn't copy them into the stored sandbox spec.
#[testkit::test]
async fn provider_credentials_are_not_stored_in_sandbox_spec(cx: &mut Context) -> testkit::Result {
    const KEY: &str = "ANTHROPIC_API_KEY";
    let provider = cx.name("nop");
    cx.install_provider(
        &provider,
        CLAUDE_CODE_PROFILE,
        &[(KEY, "sk-should-not-persist")],
    )
    .await?;
    let sandbox = cx
        .sandbox("nop")
        .spec(|spec| spec.providers = vec![provider.clone()])
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let environment = sandbox
        .spec()
        .await?
        .map(|spec| spec.environment)
        .unwrap_or_default();
    testkit::ensure!(
        !environment.contains_key(KEY),
        "the stored sandbox spec has the provider credential {KEY} in its environment"
    );
    Ok(())
}

/// Whether `value` is a credential placeholder for the environment variable
/// `key`: the plain form, or a versioned or stable one ending in `_<key>`.
fn is_placeholder_for(value: &str, key: &str) -> bool {
    value.strip_prefix(PLACEHOLDER_PREFIX).is_some_and(|token| {
        token == key || (token.starts_with(['v', 's']) && token.ends_with(&format!("_{key}")))
    })
}

fn binaries_yaml() -> String {
    PYTHON_BINARIES
        .iter()
        .map(|path| format!("  - path: {path}\n"))
        .collect()
}
