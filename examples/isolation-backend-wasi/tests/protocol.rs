// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the actual executable over TCP, using only the generated public API.
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};

use openshell_wasi_backend_example::protocol::{
    BACKEND,
    boundary::{sandbox_boundary_client::SandboxBoundaryClient, *},
    control::{sandbox_backend_client::SandboxBackendClient, *},
    metadata,
};
use tonic::{
    Code, Request,
    transport::{Channel, Endpoint},
};

const TOKEN: &str = "test-only-credential-with-at-least-32-characters";

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn authorized<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    request.set_timeout(Duration::from_secs(5));
    request
}

async fn stream_error(
    client: &mut SandboxBoundaryClient<Channel>,
    payload: boundary_chunk::Payload,
) -> Code {
    client
        .exchange(authorized(tokio_stream::iter([BoundaryChunk {
            payload: Some(payload),
        }])))
        .await
        .unwrap_err()
        .code()
}

#[tokio::test]
async fn external_service_checks_negotiation_binding_and_routes() {
    let temp = tempfile::tempdir().unwrap();
    let token_file = temp.path().join("credential");
    std::fs::write(&token_file, TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("guest.wat");
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_wasi-backend"))
            .arg("serve")
            .arg(module)
            .args([
                "--sandbox-id",
                "sandbox-a",
                "--session-id",
                "session-a",
                "--generation-id",
                "generation-a",
                "--token-file",
            ])
            .arg(token_file)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = server.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = send.send(result);
    });
    let announcement: serde_json::Value = serde_json::from_str(
        &receive
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(announcement["backend_name"], BACKEND);
    let channel = Endpoint::from_shared(format!(
        "http://{}",
        announcement["endpoint"].as_str().unwrap()
    ))
    .unwrap()
    .connect_timeout(Duration::from_secs(5))
    .timeout(Duration::from_secs(5))
    .tcp_nodelay(true)
    .connect()
    .await
    .unwrap();
    let mut client = SandboxBackendClient::new(channel.clone());
    let mut streams = SandboxBoundaryClient::new(channel);
    let response = client
        .describe(DescribeSandboxBackendRequest {
            supervisor: Some(metadata()),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.backend, Some(metadata()));
    let mut incompatible = metadata();
    incompatible.required_capabilities = vec!["openshell.sandbox.protocol".into()];
    assert_eq!(
        client
            .describe(DescribeSandboxBackendRequest {
                supervisor: Some(incompatible)
            })
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );

    let launch = OpenBoundaryRequest {
        sandbox_id: "sandbox-a".into(),
        session_id: "session-a".into(),
        generation_id: "generation-a".into(),
        backend_name: BACKEND.into(),
        driver_descriptor: serde_json::to_vec(&announcement["descriptor"]).unwrap(),
    };
    let opened = client
        .open_boundary(authorized(launch.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(!opened.boundary_id.is_empty());
    assert_eq!(
        opened.outcome,
        open_boundary_response::LaunchOutcome::Fresh as i32
    );
    assert_eq!(
        client
            .open_boundary(authorized(launch.clone()))
            .await
            .unwrap()
            .into_inner(),
        opened
    );
    assert_eq!(
        client
            .open_boundary(launch.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let mut duplicate_auth = authorized(launch.clone());
    duplicate_auth
        .metadata_mut()
        .append("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    assert_eq!(
        client
            .open_boundary(duplicate_auth)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let mut wrong_auth = authorized(launch.clone());
    wrong_auth
        .metadata_mut()
        .insert("authorization", "Bearer wrong".parse().unwrap());
    assert_eq!(
        client.open_boundary(wrong_auth).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    for field in 0..5 {
        let mut changed = launch.clone();
        match field {
            0 => changed.sandbox_id = "other".into(),
            1 => changed.session_id = "other".into(),
            2 => changed.generation_id = "other".into(),
            3 => changed.backend_name = "other".into(),
            _ => changed.driver_descriptor = b"{}".to_vec(),
        }
        assert_eq!(
            client
                .open_boundary(authorized(changed))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
    }
    assert_eq!(
        stream_error(&mut streams, boundary_chunk::Payload::Data(b"bad".to_vec())).await,
        Code::InvalidArgument
    );
    assert_eq!(
        stream_error(
            &mut streams,
            boundary_chunk::Payload::BoundaryId(String::new())
        )
        .await,
        Code::InvalidArgument
    );
    assert_eq!(
        stream_error(
            &mut streams,
            boundary_chunk::Payload::BoundaryId("other".into())
        )
        .await,
        Code::PermissionDenied
    );
    assert_eq!(
        stream_error(
            &mut streams,
            boundary_chunk::Payload::BoundaryId(opened.boundary_id.clone())
        )
        .await,
        Code::Unimplemented
    );
    let route = BoundaryChunk {
        payload: Some(boundary_chunk::Payload::BoundaryId(
            opened.boundary_id.clone(),
        )),
    };
    assert_eq!(
        streams
            .mediate(authorized(tokio_stream::iter([route])))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        client
            .suspend_boundary(authorized(SuspendBoundaryRequest {
                boundary_id: opened.boundary_id,
                session_id: launch.session_id.clone(),
                generation_id: launch.generation_id.clone(),
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        client
            .resume_boundary(authorized(ResumeBoundaryRequest {
                launch: Some(launch),
                restore_reference: vec![],
                allow_cold_start_fallback: false,
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
}
