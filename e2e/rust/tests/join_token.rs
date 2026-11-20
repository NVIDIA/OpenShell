// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use openshell_e2e::harness::{cli::run_cli, sandbox::SandboxGuard};

#[cfg(feature = "e2e-kubernetes")]
async fn workload_secret(name: &str) -> String {
    let namespace =
        std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        command.args(["--context", &context]);
    }
    let output = command
        .args([
            "-n",
            &namespace,
            "get",
            "sandboxes.agents.x-k8s.io",
            "-l",
            &format!("openshell.ai/sandbox-name={name}"),
            "-o",
            "json",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let list: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let containers = list["items"][0]["spec"]["podTemplate"]["spec"]["containers"]
        .as_array()
        .unwrap();
    let agent = containers
        .iter()
        .find(|container| container["name"] == "agent")
        .unwrap();
    assert_eq!(agent["command"][1], "--join");
    let reference = agent["env"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "OPENSHELL_JOIN_TOKEN")
        .unwrap();
    let secret = reference["valueFrom"]["secretKeyRef"]["name"]
        .as_str()
        .unwrap();
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        command.args(["--context", &context]);
    }
    let output = command
        .args([
            "-n",
            &namespace,
            "get",
            "secret",
            secret,
            "-o",
            "go-template={{range $key, $value := .data}}{{$key}}{{\"\\n\"}}{{end}}",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let keys = String::from_utf8(output.stdout).unwrap();
    assert!(keys.lines().any(|key| key == "join-token"));
    assert!(
        !keys
            .lines()
            .any(|key| matches!(key, "boundary.json" | "tls.crt" | "tls.key"))
    );
    secret.to_string()
}

#[tokio::test]
async fn join_token_starts_and_restarts_without_workload_configuration_files() {
    let mut sandbox = SandboxGuard::create(&["--env", "BOOTSTRAP_PARITY_VALUE=preserved"])
        .await
        .expect("create token-bootstrapped sandbox");
    #[cfg(feature = "e2e-kubernetes")]
    let first_secret = workload_secret(&sandbox.name).await;
    #[cfg(feature = "e2e-kubernetes")]
    assert_join_rejected(&first_secret).await;
    let check = [
        "sh",
        "-c",
        r#"set -eu
        test ! -e /.openshell/state/bootstrap/boundary.json
        test ! -e /.openshell/state/bootstrap/bootstrap-token
        test ! -e /.openshell/channel/sandbox/join-token.json
        test ! -e /.openshell/channel/sandbox/bootstrap.json
        test ! -e /.openshell/channel/sandbox/server.key
        test ! -e /.openshell/state/bootstrap/tls.key
        if env | cut -d= -f1 | grep -Eq '^OPENSHELL_(BOUNDARY_BOOTSTRAP_|JOIN_TOKEN$|SUPERVISOR_ADDRESS$)'; then exit 1; fi
        test "$BOOTSTRAP_PARITY_VALUE" = preserved
        test "$PWD" = /sandbox
        test "$1" = bootstrap-argument
        echo bootstrap-ok"#,
        "bootstrap-check",
        "bootstrap-argument",
    ];
    openshell_e2e::harness::cli::wait_for_sandbox_exec_contains(
        &sandbox.name,
        &check,
        "bootstrap-ok",
        std::time::Duration::from_secs(90),
    )
    .await
    .unwrap();
    sandbox
        .exec(&["sh", "-c", "printf preserved > /sandbox/bootstrap-parity"])
        .await
        .unwrap();
    for operation in ["stop", "start"] {
        let (output, code) = run_cli(&["sandbox", operation, &sandbox.name]).await;
        assert_eq!(code, 0, "{operation}: {output}");
    }
    #[cfg(feature = "e2e-kubernetes")]
    assert_ne!(first_secret, workload_secret(&sandbox.name).await);
    openshell_e2e::harness::cli::wait_for_sandbox_exec_contains(
        &sandbox.name,
        &check,
        "bootstrap-ok",
        std::time::Duration::from_secs(90),
    )
    .await
    .unwrap();
    assert_eq!(
        sandbox
            .exec(&["cat", "/sandbox/bootstrap-parity"])
            .await
            .unwrap()
            .trim(),
        "preserved"
    );
    sandbox.cleanup().await;
}

/// Exercise server pinning and replay rejection against the running supervisor.
#[cfg(feature = "e2e-kubernetes")]
async fn assert_join_rejected(secret: &str) {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use openshell_e2e::harness::port::{find_free_port, wait_for_port};
    use std::{process::Stdio, time::Duration};

    let namespace =
        std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let kubectl = || {
        let mut command = tokio::process::Command::new("kubectl");
        if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
            command.args(["--context", &context]);
        }
        command.args(["-n", &namespace]);
        command
    };
    let output = kubectl()
        .args(["get", "secret", secret, "-o", "json"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let data: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let decode = |key: &str| {
        String::from_utf8(
            STANDARD
                .decode(data["data"][key].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
    };
    let token = decode("join-token");
    let envelope: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.strip_prefix("OSJOIN1.").unwrap())
            .unwrap(),
    )
    .unwrap();
    let address: std::net::SocketAddr = decode("supervisor-address").parse().unwrap();
    let output = kubectl()
        .args(["get", "services", "-o", "json"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let services: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let Some(service) =
        services["items"].as_array().unwrap().iter().find(|item| {
            item["spec"]["clusterIP"].as_str() == Some(address.ip().to_string().as_str())
        })
    else {
        eprintln!("Join pin/replay probe requires a dedicated supervisor Service");
        return;
    };
    let port = find_free_port();
    let mut forward = kubectl()
        .args([
            "port-forward",
            &format!("service/{}", service["metadata"]["name"].as_str().unwrap()),
            &format!("{port}:{}", address.port()),
        ])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port("127.0.0.1", port, Duration::from_secs(20))
        .await
        .unwrap();
    probe_join_channel(port, &envelope).await;
    forward.kill().await.unwrap();
    forward.wait().await.unwrap();
}

#[cfg(feature = "e2e-kubernetes")]
#[allow(
    clippy::disallowed_methods,
    reason = "the E2E workspace does not depend on openshell-core; nodelay is set immediately"
)]
async fn probe_join_channel(port: u16, envelope: &serde_json::Value) {
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let digest: [u8; 32] = serde_json::from_value(envelope["ca_digest"].clone()).unwrap();
    for (bad_pin, kind) in [(true, "Join"), (false, "Session"), (false, "Join")] {
        let mut pin = digest;
        if bad_pin {
            pin[0] ^= 1;
        }
        let config = openshell_crypto::tls::try_client_builder()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(openshell_crypto::tls::pinned_ca_verifier(pin))
            .with_no_client_auth();
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let name = rustls::pki_types::ServerName::try_from(
            envelope["server_name"].as_str().unwrap().to_string(),
        )
        .unwrap();
        let handshake = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await;
        if bad_pin {
            assert!(
                handshake.is_err(),
                "wrong server pin must fail before sending the Join bearer"
            );
            continue;
        }
        let mut stream = handshake.expect("correct Join pin authenticates the running supervisor");
        let request =
            serde_json::to_vec(&serde_json::json!({"kind": kind, "token": envelope["token"]}))
                .unwrap();
        stream
            .write_u32(u32::try_from(request.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&request).await.unwrap();
        stream.flush().await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(15), stream.read_u32()).await;
        assert!(
            matches!(response, Ok(Err(_))),
            "Join token replay or use as a session must not return configuration"
        );
    }
}
