// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise trusted grant failure retrieval through a real REST workload.

use super::*;
use openshell_e2e::harness::container::ContainerEngine;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::E2E_WORKLOAD_IMAGE;
use serde_json::Value;
use tempfile::TempDir;
use tokio::process::Command;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint as GrpcEndpoint};

const ERROR_CANARY: &str = "grant-response-secret-canary";
const INTERMEDIATE: &str = "intermediate-closure";

async fn checked(command: &mut Command, label: &str) -> Result<String, String> {
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| format!("{label} timed out"))?
        .map_err(|_| format!("{label} could not start"))?;
    if !output.status.success() {
        return Err(format!("{label} failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn cli(args: &[&str]) -> Result<String, String> {
    checked(openshell_cmd().args(args), "closure CLI operation").await
}

fn no_secrets(output: &str) -> Result<(), String> {
    if [
        ERROR_CANARY,
        "identity-secret-canary",
        "stored-closure",
        INTERMEDIATE,
    ]
    .iter()
    .any(|secret| output.contains(secret))
    {
        return Err("grant diagnostics exposed fixture credential material".into());
    }
    Ok(())
}

// Both OAuth clients use native roots. Install the public fixture CA in the
// supervisor image and in the gateway child's own SSL_CERT_FILE. Never change
// verification flags or the test runner's process-wide environment.
struct GatewayTrust {
    directory: TempDir,
    engine: ContainerEngine,
    image: String,
    health_port: u16,
    changed: bool,
}

impl GatewayTrust {
    async fn new() -> Result<Self, String> {
        if std::env::var_os("OPENSHELL_GATEWAY_ENDPOINT").is_some()
            || std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman")
            || std::env::var("OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER")
                .is_ok_and(|value| value != "0")
        {
            return Err("grant closure requires a wrapper-owned bundled Podman gateway".into());
        }
        let args_path = std::env::var_os("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .ok_or("managed gateway arguments are missing")?;
        let bytes = fs::read(args_path).map_err(|_| "could not read gateway arguments")?;
        let args = bytes
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "gateway arguments are not UTF-8")?;
        let argument = |name| {
            args.windows(2)
                .find(|pair| pair[0] == name)
                .map(|pair| pair[1])
                .ok_or("gateway argument is missing")
        };
        let health_port = argument("--health-port")?
            .parse()
            .map_err(|_| "gateway health port is invalid")?;
        let config = fs::read_to_string(argument("--config")?)
            .map_err(|_| "could not read fixture gateway configuration")?;
        let base_image = std::env::var("OPENSHELL_SUPERVISOR_IMAGE")
            .ok()
            .or_else(|| {
                config.lines().find_map(|line| {
                    let value = line.trim().strip_prefix("supervisor_image = ")?;
                    serde_json::from_str::<String>(value).ok()
                })
            })
            .ok_or("fixture supervisor image is missing")?;
        let directory = TempDir::new().map_err(|_| "could not create private TLS fixture")?;
        generate_tls(directory.path()).await?;
        let roots = std::env::var_os("SSL_CERT_FILE").map_or_else(
            || PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
            PathBuf::from,
        );
        let mut bundle = fs::read(roots).map_err(|_| "native host CA bundle is required")?;
        bundle.push(b'\n');
        bundle.extend(
            fs::read(directory.path().join("ca.crt")).map_err(|_| "fixture CA is missing")?,
        );
        fs::write(directory.path().join("host-roots.crt"), bundle)
            .map_err(|_| "could not stage gateway roots")?;
        let context = directory.path().join("image");
        fs::create_dir(&context).map_err(|_| "could not create public image context")?;
        fs::copy(
            directory.path().join("ca.crt"),
            context.join("fixture-ca.crt"),
        )
        .map_err(|_| "could not stage public fixture CA")?;
        fs::write(context.join("Dockerfile"), format!(
            "FROM {base_image} AS original\nFROM {E2E_WORKLOAD_IMAGE} AS bundle\nUSER 0\nCOPY --from=original /etc/ssl/certs/ca-certificates.crt /tmp/roots.crt\nCOPY fixture-ca.crt /tmp/fixture-ca.crt\nRUN [\"/usr/bin/python3\", \"-c\", \"from pathlib import Path; p=Path('/tmp/roots.crt'); p.write_bytes(p.read_bytes()+Path('/tmp/fixture-ca.crt').read_bytes())\"]\nFROM {base_image}\nCOPY --from=bundle /tmp/roots.crt /etc/ssl/certs/ca-certificates.crt\n"
        )).map_err(|_| "could not write supervisor fixture Dockerfile")?;
        let engine = ContainerEngine::from_env()?;
        let image = format!(
            "localhost/openshell-grant-closure-{:016x}:fixture",
            rand::random::<u64>()
        );
        let mut build = Command::from(engine.command());
        build.args(["build", "--tag", &image]).arg(&context);
        build.kill_on_drop(true);
        let status = tokio::time::timeout(Duration::from_secs(300), build.status())
            .await
            .map_err(|_| "build trusted supervisor fixture timed out")?
            .map_err(|_| "build trusted supervisor fixture could not start")?;
        if !status.success() {
            return Err("build trusted supervisor fixture failed".into());
        }
        Ok(Self {
            directory,
            engine,
            image,
            health_port,
            changed: false,
        })
    }

    async fn install(&mut self) -> Result<(), String> {
        self.changed = true;
        let mut gateway = ManagedGateway::from_env()?.ok_or("managed gateway is missing")?;
        gateway.set_supervisor_image(&self.image);
        gateway.set_native_ca_bundle(self.directory.path().join("host-roots.crt"));
        gateway.stop()?;
        gateway.start()?;
        self.wait_ready().await
    }

    async fn wait_ready(&self) -> Result<(), String> {
        let url = format!("http://127.0.0.1:{}/healthz", self.health_port);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            if checked(
                Command::new("curl").args([
                    "--noproxy",
                    "*",
                    "--silent",
                    "--fail",
                    "--max-time",
                    "2",
                    &url,
                ]),
                "gateway health probe",
            )
            .await
            .is_ok()
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("trusted fixture gateway did not become healthy".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn restore(&mut self) -> Result<(), String> {
        if self.changed {
            let gateway = ManagedGateway::from_env()?.ok_or("managed gateway is missing")?;
            gateway.stop()?;
            gateway.start()?;
            self.wait_ready().await?;
            self.changed = false;
        }
        let mut remove = Command::from(self.engine.command());
        checked(
            remove.args(["image", "rm", "--force", &self.image]),
            "remove supervisor fixture image",
        )
        .await?;
        Ok(())
    }
}

async fn generate_tls(directory: &Path) -> Result<(), String> {
    checked(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=OpenShell grant fixture CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
            ])
            .arg(directory.join("ca.key"))
            .arg("-out")
            .arg(directory.join("ca.crt")),
        "generate fixture CA",
    )
    .await?;
    checked(
        Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
            ])
            .arg(directory.join("server.key"))
            .arg("-out")
            .arg(directory.join("server.csr")),
        "generate token service CSR",
    )
    .await?;
    fs::write(directory.join("extensions"), "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        .map_err(|_| "could not write token service certificate extensions")?;
    checked(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "1", "-in"])
            .arg(directory.join("server.csr"))
            .arg("-CA")
            .arg(directory.join("ca.crt"))
            .arg("-CAkey")
            .arg(directory.join("ca.key"))
            .arg("-CAcreateserial")
            .arg("-extfile")
            .arg(directory.join("extensions"))
            .arg("-out")
            .arg(directory.join("server.crt")),
        "sign token service certificate",
    )
    .await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Mode {
    IntermediateAuthorization,
    FinalAuthorization,
    Bare401,
    Success,
}

struct TokenService {
    mode: Mutex<Mode>,
    requests: Mutex<Vec<(bool, String)>>,
}

async fn token_server(
    directory: &Path,
    port: u16,
    state: Arc<TokenService>,
) -> Result<FixtureHandle, String> {
    let certificate =
        fs::read(directory.join("server.crt")).map_err(|_| "token certificate is missing")?;
    let key = fs::read(directory.join("server.key")).map_err(|_| "token key is missing")?;
    let certificates = rustls_pemfile::certs(&mut certificate.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid token certificate")?;
    let private_key = rustls_pemfile::private_key(&mut key.as_slice())
        .map_err(|_| "invalid token key")?
        .ok_or("empty token key")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| "invalid token TLS configuration")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|_| "could not bind HTTPS token fixture")?;
    let endpoint = format!("https://127.0.0.1:{port}/token");
    let task = tokio::spawn(async move {
        let mut requests = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    let (acceptor, state, endpoint) = (acceptor.clone(), state.clone(), endpoint.clone());
                    requests.spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else { return; };
                        let Ok(Some(request)) = read_route_fixture_request(&mut stream, None).await else { return; };
                        let fields = token_form(&request);
                        let assertion = fields.get("client_assertion").map_or("", String::as_str);
                        let mut validation = Validation::new(Algorithm::RS256);
                        validation.set_audience(&[&endpoint]);
                        validation.set_issuer(&[ISSUER]);
                        let jwks: Value = serde_json::from_slice(&jwks()).unwrap();
                        let key = DecodingKey::from_rsa_components(jwks["keys"][0]["n"].as_str().unwrap(), jwks["keys"][0]["e"].as_str().unwrap()).unwrap();
                        if jsonwebtoken::decode::<Value>(assertion, &key, &validation).is_err() { return; }
                        let subject = fields.get("subject_token").map_or("", String::as_str);
                        let final_hop = subject == INTERMEDIATE;
                        if !final_hop && !subject.starts_with("stored-closure") { return; }
                        let request_id = request.split_once("\r\n\r\n").unwrap().0.lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("x-openshell-request-id"))
                            .map_or("", |(_, value)| value.trim()).to_owned();
                        state.requests.lock().unwrap().push((final_hop, request_id));
                        let mode = *state.mode.lock().unwrap();
                        let authorization = matches!((mode, final_hop), (Mode::IntermediateAuthorization, false) | (Mode::FinalAuthorization, true));
                        let (status, body) = if authorization {
                            ("409 Conflict", json!({"error":"provider_authorization_required", "openshell_error_contract":"openshell.token-grant.v1", "error_description":ERROR_CANARY, "authorization_url":format!("https://{ERROR_CANARY}.invalid/")}))
                        } else if matches!((mode, final_hop), (Mode::Bare401, true)) {
                            ("401 Unauthorized", json!({"error":"invalid_client", "error_description":ERROR_CANARY}))
                        } else {
                            ("200 OK", json!({"access_token":if final_hop {"final-b"} else {INTERMEDIATE}, "token_type":"Bearer", "expires_in":0}))
                        };
                        let body = body.to_string();
                        let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
                _ = requests.join_next(), if !requests.is_empty() => {}
            }
        }
    });
    Ok(FixtureHandle { task })
}

async fn probe(sandbox: &SandboxGuard, target_port: u16, denied: bool) -> Result<String, String> {
    let script = format!(
        r"import urllib.request, urllib.error, uuid
try:
    response = urllib.request.urlopen('http://host.openshell.internal:{target_port}/closure/probe', timeout=10)
    response.read()
    assert not {denied}, 'grant unexpectedly forwarded'
    print('success')
except urllib.error.HTTPError as error:
    body = error.read().decode('utf-8', errors='replace')
    text = str(error.headers) + body
    assert {denied} and error.code == 502, 'unexpected grant refusal'
    for value in ['{ERROR_CANARY}', 'identity-secret-canary', 'stored-closure', '{INTERMEDIATE}', 'final-b', 'provider_authorization_required', 'workload_identity_rejected', 'authorization_url']:
        assert value not in text, 'grant refusal exposed private diagnostics'
    request_id = error.headers.get('x-openshell-request-id', '')
    assert str(uuid.UUID(request_id)) == request_id, 'invalid refusal request ID'
    print(request_id)
",
        denied = if denied { "True" } else { "False" }
    );
    let output = sandbox.exec(&["python3", "-c", &script]).await?;
    no_secrets(&output)?;
    Ok(output.trim().to_owned())
}

async fn snapshot(name: &str) -> Result<Value, String> {
    let output = cli(&["sandbox", "get", name, "--output", "json"]).await?;
    no_secrets(&output)?;
    serde_json::from_str(&output).map_err(|_| "sandbox snapshot was invalid JSON".into())
}

async fn wait_cause(name: &str, request_id: Option<&str>) -> Result<Value, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let value = snapshot(name).await?;
        let cause = value
            .get("last_token_grant_failure")
            .ok_or("sandbox snapshot omitted grant failures")?;
        if request_id.map_or_else(
            || cause.is_null(),
            |id| cause["failure"]["request_id"] == id,
        ) {
            return Ok(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("grant observation did not settle".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn check_cause(
    value: &Value,
    port: u16,
    code: &str,
    stage: &str,
    recovery: &str,
) -> Result<(), String> {
    let cause = &value["last_token_grant_failure"];
    let failure = &cause["failure"];
    if cause["destination_host"] != "host.openshell.internal"
        || cause["destination_port"].as_u64() != Some(u64::from(port))
        || failure["code"] != code
        || failure["stage"] != stage
        || failure["recovery_action"] != recovery
    {
        return Err("trusted grant cause did not match the refused exchange".into());
    }
    if !value["endpoint_statuses"]
        .as_array()
        .is_some_and(Vec::is_empty)
    {
        return Err("REST fixture unexpectedly depended on MCP endpoint status".into());
    }
    Ok(())
}

async fn check_logs(sandbox: &SandboxGuard, request_id: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let logs = cli(&[
            "logs",
            &sandbox.name,
            "--source",
            "sandbox",
            "--since",
            "5m",
        ])
        .await?;
        no_secrets(&logs)?;
        if logs
            .lines()
            .any(|line| line.contains(request_id) && line.contains("Token grant failed"))
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("supervisor log omitted the refused request ID".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let gateway_log =
        std::env::var_os("OPENSHELL_E2E_GATEWAY_LOG").ok_or("gateway log path is missing")?;
    let gateway =
        fs::read_to_string(gateway_log).map_err(|_| "could not read gateway fixture log")?;
    no_secrets(&gateway)?;
    if !gateway
        .lines()
        .any(|line| line.contains(request_id) && line.contains("provider_authorization_required"))
    {
        return Err("gateway log omitted the classified exchange".into());
    }
    let denials = sandbox.exec(&["python3", "-c", "import urllib.request; print(urllib.request.urlopen('http://policy.local/v1/denials?last=20').read().decode())"]).await?;
    no_secrets(&denials)?;
    if !denials.contains(request_id) || denials.contains("provider_authorization_required") {
        return Err("agent denial stream lost correlation or exposed classification".into());
    }
    Ok(())
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetSandbox {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    workspace_scope: Option<Workspace>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct Workspace {
    #[prost(string, tag = "1")]
    workspace: String,
}
#[derive(Clone, PartialEq, prost::Message)]
struct Empty {}

async fn assert_untrusted_reader(name: &str, bearer: Option<&str>) -> Result<(), String> {
    let gateway = std::env::var("OPENSHELL_GATEWAY").map_err(|_| "gateway name is missing")?;
    let home = std::env::var_os("XDG_CONFIG_HOME").ok_or("gateway config directory is missing")?;
    let directory = PathBuf::from(home).join("openshell/gateways").join(gateway);
    let metadata: Value = serde_json::from_slice(
        &fs::read(directory.join("metadata.json")).map_err(|_| "gateway metadata is missing")?,
    )
    .map_err(|_| "gateway metadata is invalid")?;
    let endpoint = metadata["gateway_endpoint"]
        .as_str()
        .ok_or("gateway endpoint is missing")?;
    let ca = fs::read(directory.join("mtls/ca.crt")).map_err(|_| "gateway CA is missing")?;
    let channel = GrpcEndpoint::from_shared(endpoint.to_owned())
        .map_err(|_| "invalid gateway endpoint")?
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))
        .map_err(|_| "invalid gateway TLS configuration")?
        .connect()
        .await
        .map_err(|_| "could not connect untrusted reader over verified TLS")?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|_| "untrusted reader transport is not ready")?;
    let mut request = Request::new(GetSandbox {
        name: name.to_owned(),
        workspace_scope: Some(Workspace {
            workspace: "default".into(),
        }),
    });
    if let Some(token) = bearer {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|_| "invalid fixture bearer")?,
        );
    }
    let result: Result<Response<Empty>, Status> = client
        .unary(
            request,
            http::uri::PathAndQuery::from_static("/openshell.v1.OpenShell/GetSandbox"),
            tonic_prost::ProstCodec::default(),
        )
        .await;
    match result {
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ) =>
        {
            Ok(())
        }
        _ => Err("untrusted reader was not denied access to grant details".into()),
    }
}

async fn supervisor_token(engine: &ContainerEngine, name: &str) -> Result<String, String> {
    let mut list = Command::from(engine.command());
    let output = checked(
        list.args([
            "ps",
            "--quiet",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={name}"),
            "--filter",
            "label=openshell.ai/isolation-role=supervisor",
        ]),
        "locate fixture supervisor",
    )
    .await?;
    let ids = output.lines().collect::<Vec<_>>();
    let [id] = ids.as_slice() else {
        return Err("fixture supervisor is ambiguous".into());
    };
    let directory =
        TempDir::new().map_err(|_| "could not create private authentication fixture")?;
    let path = directory.path().join("auth.json");
    let mut copy = Command::from(engine.command());
    checked(
        copy.arg("cp")
            .arg(format!("{id}:/.openshell/supervisor/auth.json"))
            .arg(&path),
        "copy private fixture supervisor authentication",
    )
    .await?;
    let value: Value =
        serde_json::from_slice(&fs::read(&path).map_err(|_| "fixture authentication is missing")?)
            .map_err(|_| "fixture authentication is invalid")?;
    value["gateway_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or("fixture supervisor token is missing".into())
}

async fn failure_cases(
    sandbox: &SandboxGuard,
    port: u16,
    service: &TokenService,
    denied_identity: &AtomicBool,
) -> Result<(), String> {
    for (mode, stage) in [
        (Mode::IntermediateAuthorization, "intermediate_exchange"),
        (Mode::FinalAuthorization, "token_endpoint"),
    ] {
        *service.mode.lock().unwrap() = mode;
        let request_id = probe(sandbox, port, true).await?;
        let value = wait_cause(&sandbox.name, Some(&request_id)).await?;
        check_cause(
            &value,
            port,
            "provider_authorization_required",
            stage,
            "reauthorize",
        )?;
        if value["last_token_grant_failure"]["failure"]["upstream_http_status"] != 409 {
            return Err("trusted cause lost the token service HTTP status".into());
        }
        let hops = {
            let requests = service.requests.lock().unwrap();
            requests
                .iter()
                .filter(|(_, id)| id == &request_id)
                .map(|(final_hop, _)| *final_hop)
                .collect::<Vec<_>>()
        };
        let expected = if stage == "intermediate_exchange" {
            vec![false]
        } else {
            vec![false, true]
        };
        if hops != expected {
            return Err(
                "actual token-service hops did not preserve the workload request ID".into(),
            );
        }
        if stage == "intermediate_exchange" {
            check_logs(sandbox, &request_id).await?;
        }
    }
    *service.mode.lock().unwrap() = Mode::Bare401;
    let request_id = probe(sandbox, port, true).await?;
    let value = wait_cause(&sandbox.name, Some(&request_id)).await?;
    check_cause(
        &value,
        port,
        "unclassified",
        "token_endpoint",
        "investigate",
    )?;
    let requests = service.requests.lock().unwrap().len();
    denied_identity.store(true, Ordering::SeqCst);
    let request_id = probe(sandbox, port, true).await?;
    let value = wait_cause(&sandbox.name, Some(&request_id)).await?;
    denied_identity.store(false, Ordering::SeqCst);
    check_cause(
        &value,
        port,
        "workload_identity_rejected",
        "workload_identity",
        "fix_configuration",
    )?;
    if service.requests.lock().unwrap().len() != requests {
        return Err("rejected workload identity reached the token service".into());
    }
    Ok(())
}

async fn create_rest_fixture(
    name: &str,
    token_port: u16,
    port: u16,
) -> Result<SandboxGuard, String> {
    let profile = write_route_profile(name, token_port, port, "closure");
    let contents = fs::read_to_string(profile.path())
        .map_err(|_| "fixture profile is missing")?
        .replace("http://127.0.0.1:", "https://127.0.0.1:")
        .replace("cache_ttl_seconds: 300", "cache_ttl: \"0s\"");
    fs::write(profile.path(), contents).map_err(|_| "could not set verified token endpoint")?;
    run_cli(&[
        "profile",
        "import",
        "-f",
        profile.path().to_str().ok_or("profile path is invalid")?,
    ])
    .await?;
    run_cli(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        name,
        "--credential",
        "subject_token=stored-closure",
    ])
    .await?;
    SandboxGuard::create_keep_with_args(
        &["--name", name, "--provider", name],
        &["sh", "-lc", &sandbox_script()],
        "token-server-ready",
    )
    .await
}

async fn recovery_cases(
    sandbox: &SandboxGuard,
    port: u16,
    service: &TokenService,
) -> Result<(), String> {
    *service.mode.lock().unwrap() = Mode::Success;
    if probe(sandbox, port, false).await? != "success" {
        return Err("reauthorized request did not reach its destination".into());
    }
    wait_cause(&sandbox.name, None).await?;
    *service.mode.lock().unwrap() = Mode::FinalAuthorization;
    let request_id = probe(sandbox, port, true).await?;
    wait_cause(&sandbox.name, Some(&request_id)).await?;
    run_cli(&[
        "provider",
        "update",
        &sandbox.name,
        "--credential",
        "subject_token=stored-closure-replacement",
    ])
    .await?;
    wait_cause(&sandbox.name, None).await?;
    Ok(())
}

#[tokio::test]
async fn verified_grant_failures_reach_trusted_rest_status_and_recover() -> Result<(), String> {
    let _fixture_guard = SPIFFE_FIXTURE_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let gateway_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET")
            .map_err(|_| "gateway Workload API fixture is missing")?,
    );
    let provider_socket = PathBuf::from(
        std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET")
            .map_err(|_| "provider Workload API fixture is missing")?,
    );
    let token_port = std::env::var("OPENSHELL_E2E_TOKEN_PORT").map_or_else(
        |_| Ok(find_free_port()),
        |value| {
            value
                .parse::<u16>()
                .map_err(|_| "invalid fixed token fixture port")
        },
    )?;
    let mut trust = GatewayTrust::new().await?;
    let gateway_spiffe = start_spiffe_workload_api(
        &gateway_socket,
        &format!("spiffe://{TRUST_DOMAIN}/openshell/gateway"),
    )
    .await;
    let deny_identity = Arc::new(AtomicBool::new(false));
    let provider_spiffe = start_controlled_spiffe_workload_api(
        &provider_socket,
        &format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e"),
        deny_identity.clone(),
    )
    .await;
    let port = find_free_port();
    let service = Arc::new(TokenService {
        mode: Mutex::new(Mode::IntermediateAuthorization),
        requests: Mutex::new(Vec::new()),
    });
    let tokens = match token_server(trust.directory.path(), token_port, service.clone()).await {
        Ok(tokens) => tokens,
        Err(error) => {
            trust.restore().await?;
            return Err(error);
        }
    };
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_bytes = Arc::new(AtomicUsize::new(0));
    let target = start_route_target(port, observed.clone(), observed_bytes.clone()).await;
    let name = format!("closure-{:08x}", rand::random::<u32>());
    let mut sandbox = None;
    let mut other = None;
    let result = async {
        trust.install().await?;
        sandbox = Some(create_rest_fixture(&name, token_port, port).await?);
        let active = sandbox.as_ref().unwrap();
        failure_cases(active, port, &service, &deny_identity).await?;
        if !observed.lock().unwrap().is_empty() || observed_bytes.load(Ordering::Relaxed) != 0 {
            return Err("a refused grant forwarded protected request bytes".into());
        }
        assert_untrusted_reader(&name, None).await?;
        let bearer = supervisor_token(&trust.engine, &name).await?;
        assert_untrusted_reader(&name, Some(&bearer)).await?;
        let other_name = format!("other-{:08x}", rand::random::<u32>());
        other = Some(
            SandboxGuard::create_keep_with_args(
                &["--name", &other_name, "--no-auto-providers"],
                &["sh", "-lc", &sandbox_script()],
                "token-server-ready",
            )
            .await?,
        );
        assert_untrusted_reader(&other_name, Some(&bearer)).await?;
        recovery_cases(active, port, &service).await?;
        Ok::<(), String>(())
    }
    .await;
    if let Some(mut sandbox) = sandbox {
        sandbox.cleanup().await;
    }
    if let Some(mut other) = other {
        other.cleanup().await;
    }
    run_cli_ignore_error(&["sandbox", "delete", &name]).await;
    run_cli_ignore_error(&["provider", "delete", &name, "--yes"]).await;
    run_cli_ignore_error(&["profile", "delete", &name, "--yes"]).await;
    let drained = target.drain().await;
    tokens.shutdown().await;
    provider_spiffe.shutdown().await;
    gateway_spiffe.shutdown().await;
    let restored = trust.restore().await;
    result?;
    drained?;
    restored?;
    let requests = observed.lock().unwrap();
    if requests.len() != 1
        || observed_bytes.load(Ordering::Relaxed)
            != requests.iter().map(|request| request.bytes).sum::<usize>()
    {
        return Err("grant recovery reached an unexpected number of protected requests".into());
    }
    Ok(())
}
