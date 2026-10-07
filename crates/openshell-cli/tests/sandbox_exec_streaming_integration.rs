// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

mod helpers;

use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use helpers::{build_ca, build_client_cert, build_server_cert};
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{self, exec_sandbox_event, exec_sandbox_input};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const DEADLINE: Duration = Duration::from_secs(10);
const STDIN_LIMIT: usize = 4 * 1024 * 1024;
type EventStream = ReceiverStream<Result<proto::ExecSandboxEvent, Status>>;

#[derive(Clone, Copy)]
enum Scenario {
    Echo,
    EarlyExit,
    ErrorAfterExit,
    ErrorAfterInput,
}

#[derive(Default)]
struct Calls {
    lookups: usize,
    unary: usize,
    starts: Vec<proto::ExecSandboxRequest>,
    input_bytes: usize,
}

#[derive(Clone)]
struct MockGateway {
    scenario: Scenario,
    calls: Arc<Mutex<Calls>>,
}

fn stdout(data: impl Into<Vec<u8>>) -> proto::ExecSandboxEvent {
    proto::ExecSandboxEvent {
        payload: Some(exec_sandbox_event::Payload::Stdout(
            proto::ExecSandboxStdout { data: data.into() },
        )),
    }
}

fn exit(code: i32) -> proto::ExecSandboxEvent {
    proto::ExecSandboxEvent {
        payload: Some(exec_sandbox_event::Payload::Exit(proto::ExecSandboxExit {
            exit_code: code,
        })),
    }
}

impl MockGateway {
    async fn exchange(
        self,
        mut input: tonic::Streaming<proto::ExecSandboxInput>,
        output: mpsc::Sender<Result<proto::ExecSandboxEvent, Status>>,
    ) {
        let Some(exec_sandbox_input::Payload::Start(start)) = input
            .message()
            .await
            .expect("read start frame")
            .expect("start frame")
            .payload
        else {
            panic!("first frame must start the command");
        };
        assert!(!start.tty, "streaming pipes must not allocate a TTY");
        assert!(start.stdin.is_empty(), "stdin must follow the start frame");
        self.calls.lock().unwrap().starts.push(start);

        match self.scenario {
            Scenario::EarlyExit | Scenario::ErrorAfterExit => {
                let _ = output.send(Ok(stdout(b"before-exit\n".to_vec()))).await;
                let _ = output.send(Ok(exit(0))).await;
                if matches!(self.scenario, Scenario::ErrorAfterExit) {
                    send_trailer_error(&output).await;
                }
                return;
            }
            Scenario::Echo | Scenario::ErrorAfterInput => {}
        }

        loop {
            let message = tokio::select! {
                biased;
                () = output.closed() => return,
                message = input.message() => message,
            };
            match message {
                Ok(Some(frame)) => match frame.payload {
                    Some(exec_sandbox_input::Payload::Stdin(bytes)) => {
                        self.calls.lock().unwrap().input_bytes += bytes.len();
                        if matches!(self.scenario, Scenario::Echo)
                            && output.send(Ok(stdout(bytes))).await.is_err()
                        {
                            return;
                        }
                    }
                    None => return,
                    unexpected => panic!("unexpected input after start: {unexpected:?}"),
                },
                Ok(None) => break,
                Err(_) => return,
            }
        }

        match self.scenario {
            Scenario::Echo => {
                let _ = output.send(Ok(stdout(b"after-eof\n".to_vec()))).await;
                let _ = output
                    .send(Ok(proto::ExecSandboxEvent {
                        payload: Some(exec_sandbox_event::Payload::Stderr(
                            proto::ExecSandboxStderr {
                                data: b"remote-stderr\n".to_vec(),
                            },
                        )),
                    }))
                    .await;
                let _ = output.send(Ok(exit(7))).await;
            }
            Scenario::ErrorAfterInput => {
                let _ = output.send(Ok(exit(0))).await;
                send_trailer_error(&output).await;
            }
            _ => unreachable!(),
        }
    }
}

async fn send_trailer_error(output: &mpsc::Sender<Result<proto::ExecSandboxEvent, Status>>) {
    // Separate the Exit message from the failing final gRPC status. A client
    // that stops at Exit reports success before this failure arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = output
        .send(Err(Status::internal("failure after exit")))
        .await;
}

// Generate unused trait methods inside the async_trait expansion so this mock
// implements only the RPC behavior under test without hand-written boilerplate.
macro_rules! mock_gateway {
    (
        unary { $( $method:ident($request:ty) -> $response:ty; )* }
        client_stream { $( $client_method:ident($client_request:ty) -> $client_response:ty; )* }
        server_stream { $( $server_method:ident($server_request:ty) -> $stream_type:ident($server_response:ty); )* }
        bidi { $( $bidi_method:ident($bidi_request:ty) -> $bidi_type:ident($bidi_response:ty); )* }
    ) => {
        #[tonic::async_trait]
        impl OpenShell for MockGateway {
            $(async fn $method(&self, _: Request<$request>) -> Result<Response<$response>, Status> {
                Err(Status::unimplemented("unused test RPC"))
            })*
            $(async fn $client_method(&self, _: Request<tonic::Streaming<$client_request>>) -> Result<Response<$client_response>, Status> {
                Err(Status::unimplemented("unused test RPC"))
            })*
            $(type $stream_type = ReceiverStream<Result<$server_response, Status>>;
            async fn $server_method(&self, _: Request<$server_request>) -> Result<Response<Self::$stream_type>, Status> {
                Err(Status::unimplemented("unused test RPC"))
            })*
            $(type $bidi_type = ReceiverStream<Result<$bidi_response, Status>>;
            async fn $bidi_method(&self, _: Request<tonic::Streaming<$bidi_request>>) -> Result<Response<Self::$bidi_type>, Status> {
                Err(Status::unimplemented("unused test RPC"))
            })*

            async fn get_sandbox(&self, _: Request<proto::GetSandboxRequest>) -> Result<Response<proto::SandboxResponse>, Status> {
                self.calls.lock().unwrap().lookups += 1;
                Ok(Response::new(proto::SandboxResponse {
                    sandbox: Some(proto::Sandbox {
                        metadata: Some(proto::datamodel::v1::ObjectMeta {
                            id: "test-id".to_string(),
                            name: "test-sandbox".to_string(),
                            workspace: "default".to_string(),
                            ..Default::default()
                        }),
                        status: Some(proto::SandboxStatus {
                            phase: proto::SandboxPhase::Ready.into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
            }

            type ExecSandboxStream = EventStream;
            async fn exec_sandbox(&self, _: Request<proto::ExecSandboxRequest>) -> Result<Response<EventStream>, Status> {
                self.calls.lock().unwrap().unary += 1;
                Err(Status::unimplemented("test requires streaming exec"))
            }

            type ExecSandboxInteractiveStream = EventStream;
            async fn exec_sandbox_interactive(&self, request: Request<tonic::Streaming<proto::ExecSandboxInput>>) -> Result<Response<EventStream>, Status> {
                let (sender, receiver) = mpsc::channel(1);
                let service = self.clone();
                tokio::spawn(async move {
                    service.exchange(request.into_inner(), sender).await;
                });
                Ok(Response::new(ReceiverStream::new(receiver)))
            }
        }
    };
}

mock_gateway! {
    unary {
        health(proto::HealthRequest) -> proto::HealthResponse;
        get_current_user(proto::GetCurrentUserRequest) -> proto::GetCurrentUserResponse;
        get_gateway_info(proto::GetGatewayInfoRequest) -> proto::GetGatewayInfoResponse;
        create_sandbox(proto::CreateSandboxRequest) -> proto::SandboxResponse;
        begin_rootfs_tar_staging(proto::BeginRootfsTarStagingRequest) -> proto::BeginRootfsTarStagingResponse;
        list_sandboxes(proto::ListSandboxesRequest) -> proto::ListSandboxesResponse;
        create_sandbox_template(proto::CreateSandboxTemplateRequest) -> proto::SandboxTemplateResponse;
        get_sandbox_template(proto::GetSandboxTemplateRequest) -> proto::SandboxTemplateResponse;
        list_sandbox_templates(proto::ListSandboxTemplatesRequest) -> proto::ListSandboxTemplatesResponse;
        delete_sandbox_template(proto::DeleteSandboxTemplateRequest) -> proto::DeleteSandboxTemplateResponse;
        list_sandbox_providers(proto::ListSandboxProvidersRequest) -> proto::ListSandboxProvidersResponse;
        attach_sandbox_provider(proto::AttachSandboxProviderRequest) -> proto::AttachSandboxProviderResponse;
        detach_sandbox_provider(proto::DetachSandboxProviderRequest) -> proto::DetachSandboxProviderResponse;
        get_sandbox_provider_status(proto::GetSandboxProviderStatusRequest) -> proto::GetSandboxProviderStatusResponse;
        delete_sandbox(proto::DeleteSandboxRequest) -> proto::DeleteSandboxResponse;
        stop_sandbox(proto::StopSandboxRequest) -> proto::SandboxResponse;
        start_sandbox(proto::StartSandboxRequest) -> proto::SandboxResponse;
        create_ssh_session(proto::CreateSshSessionRequest) -> proto::CreateSshSessionResponse;
        expose_service(proto::ExposeServiceRequest) -> proto::ServiceEndpointResponse;
        get_service(proto::GetServiceRequest) -> proto::ServiceEndpointResponse;
        list_services(proto::ListServicesRequest) -> proto::ListServicesResponse;
        delete_service(proto::DeleteServiceRequest) -> proto::DeleteServiceResponse;
        revoke_ssh_session(proto::RevokeSshSessionRequest) -> proto::RevokeSshSessionResponse;
        create_provider(proto::CreateProviderRequest) -> proto::ProviderResponse;
        get_provider(proto::GetProviderRequest) -> proto::ProviderResponse;
        list_providers(proto::ListProvidersRequest) -> proto::ListProvidersResponse;
        list_provider_profiles(proto::ListProviderProfilesRequest) -> proto::ListProviderProfilesResponse;
        get_provider_profile(proto::GetProviderProfileRequest) -> proto::ProviderProfileResponse;
        import_provider_profiles(proto::ImportProviderProfilesRequest) -> proto::ImportProviderProfilesResponse;
        update_provider_profiles(proto::UpdateProviderProfilesRequest) -> proto::UpdateProviderProfilesResponse;
        lint_provider_profiles(proto::LintProviderProfilesRequest) -> proto::LintProviderProfilesResponse;
        update_provider(proto::UpdateProviderRequest) -> proto::ProviderResponse;
        get_provider_refresh_status(proto::GetProviderRefreshStatusRequest) -> proto::GetProviderRefreshStatusResponse;
        configure_provider_refresh(proto::ConfigureProviderRefreshRequest) -> proto::ConfigureProviderRefreshResponse;
        rotate_provider_credential(proto::RotateProviderCredentialRequest) -> proto::RotateProviderCredentialResponse;
        delete_provider_refresh(proto::DeleteProviderRefreshRequest) -> proto::DeleteProviderRefreshResponse;
        delete_provider(proto::DeleteProviderRequest) -> proto::DeleteProviderResponse;
        delete_provider_profile(proto::DeleteProviderProfileRequest) -> proto::DeleteProviderProfileResponse;
        get_sandbox_config(proto::GetSandboxConfigRequest) -> proto::GetSandboxConfigResponse;
        get_gateway_config(proto::GetGatewayConfigRequest) -> proto::GetGatewayConfigResponse;
        update_config(proto::UpdateConfigRequest) -> proto::UpdateConfigResponse;
        get_sandbox_policy_status(proto::GetSandboxPolicyStatusRequest) -> proto::GetSandboxPolicyStatusResponse;
        list_sandbox_policies(proto::ListSandboxPoliciesRequest) -> proto::ListSandboxPoliciesResponse;
        report_policy_status(proto::ReportPolicyStatusRequest) -> proto::ReportPolicyStatusResponse;
        report_endpoint_status(proto::ReportEndpointStatusRequest) -> proto::ReportEndpointStatusResponse;
        report_provider_readiness(proto::ReportProviderReadinessRequest) -> proto::ReportProviderReadinessResponse;
        report_sandbox_configuration(proto::ReportSandboxConfigurationRequest) -> proto::ReportSandboxConfigurationResponse;
        get_sandbox_provider_environment(proto::GetSandboxProviderEnvironmentRequest) -> proto::GetSandboxProviderEnvironmentResponse;
        exchange_provider_subject_token(proto::ExchangeProviderSubjectTokenRequest) -> proto::ExchangeProviderSubjectTokenResponse;
        get_sandbox_logs(proto::GetSandboxLogsRequest) -> proto::GetSandboxLogsResponse;
        report_main_process_exit(proto::ReportMainProcessExitRequest) -> proto::ReportMainProcessExitResponse;
        finalize_main_process_exit(proto::FinalizeMainProcessExitRequest) -> proto::FinalizeMainProcessExitResponse;
        peer_report_provider_readiness(proto::ReportProviderReadinessRequest) -> proto::ReportProviderReadinessResponse;
        peer_report_endpoint_status(proto::ReportEndpointStatusRequest) -> proto::ReportEndpointStatusResponse;
        peer_get_sandbox_provider_status(proto::GetSandboxProviderStatusRequest) -> proto::GetSandboxProviderStatusResponse;
        peer_notify_config_update(proto::PeerNotifyConfigUpdateRequest) -> proto::PeerNotifyConfigUpdateResponse;
        get_config_update_operation(proto::GetConfigUpdateOperationRequest) -> proto::GetConfigUpdateOperationResponse;
        submit_policy_analysis(proto::SubmitPolicyAnalysisRequest) -> proto::SubmitPolicyAnalysisResponse;
        get_draft_policy(proto::GetDraftPolicyRequest) -> proto::GetDraftPolicyResponse;
        approve_draft_chunk(proto::ApproveDraftChunkRequest) -> proto::ApproveDraftChunkResponse;
        reject_draft_chunk(proto::RejectDraftChunkRequest) -> proto::RejectDraftChunkResponse;
        approve_all_draft_chunks(proto::ApproveAllDraftChunksRequest) -> proto::ApproveAllDraftChunksResponse;
        edit_draft_chunk(proto::EditDraftChunkRequest) -> proto::EditDraftChunkResponse;
        undo_draft_chunk(proto::UndoDraftChunkRequest) -> proto::UndoDraftChunkResponse;
        clear_draft_chunks(proto::ClearDraftChunksRequest) -> proto::ClearDraftChunksResponse;
        get_draft_history(proto::GetDraftHistoryRequest) -> proto::GetDraftHistoryResponse;
        issue_sandbox_token(proto::IssueSandboxTokenRequest) -> proto::IssueSandboxTokenResponse;
        refresh_sandbox_token(proto::RefreshSandboxTokenRequest) -> proto::RefreshSandboxTokenResponse;
        create_workspace(proto::CreateWorkspaceRequest) -> proto::CreateWorkspaceResponse;
        get_workspace(proto::GetWorkspaceRequest) -> proto::GetWorkspaceResponse;
        list_workspaces(proto::ListWorkspacesRequest) -> proto::ListWorkspacesResponse;
        delete_workspace(proto::DeleteWorkspaceRequest) -> proto::DeleteWorkspaceResponse;
        add_workspace_member(proto::AddWorkspaceMemberRequest) -> proto::AddWorkspaceMemberResponse;
        remove_workspace_member(proto::RemoveWorkspaceMemberRequest) -> proto::RemoveWorkspaceMemberResponse;
        list_workspace_members(proto::ListWorkspaceMembersRequest) -> proto::ListWorkspaceMembersResponse;
    }
    client_stream {
        push_sandbox_logs(proto::PushSandboxLogsRequest) -> proto::PushSandboxLogsResponse;
    }
    server_stream {
        watch_sandbox(proto::WatchSandboxRequest) -> WatchSandboxStream(proto::SandboxStreamEvent);
    }
    bidi {
        forward_tcp(proto::TcpForwardFrame) -> ForwardTcpStream(proto::TcpForwardFrame);
        connect_supervisor(proto::SupervisorMessage) -> ConnectSupervisorStream(proto::GatewayMessage);
        relay_stream(proto::RelayFrame) -> RelayStreamStream(proto::RelayFrame);
        peer_relay(proto::PeerRelayFrame) -> PeerRelayStream(proto::PeerRelayFrame);
    }
}

struct TestGateway {
    endpoint: String,
    config: tempfile::TempDir,
    calls: Arc<Mutex<Calls>>,
    task: JoinHandle<()>,
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestGateway {
    async fn start(scenario: Scenario) -> Self {
        let (ca, ca_key) = build_ca();
        let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
        let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
        let config = tempfile::tempdir().unwrap();
        let certs = config.path().join("openshell/gateways/test-gateway/mtls");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ca.crt"), ca.pem()).unwrap();
        std::fs::write(certs.join("tls.crt"), client_cert).unwrap();
        std::fs::write(certs.join("tls.key"), client_key).unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(server_cert, server_key))
            .client_ca_root(Certificate::from_pem(ca.pem()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let calls = Arc::new(Mutex::new(Calls::default()));
        let service = MockGateway {
            scenario,
            calls: Arc::clone(&calls),
        };
        let task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(OpenShellServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        Self {
            endpoint,
            config,
            calls,
            task,
        }
    }

    fn command(&self) -> Command {
        // Run the same subprocess regression against an official CLI when
        // establishing that the unfixed version reports the wrong result.
        let baseline = std::env::var_os("OPENSHELL_STREAMING_TEST_BASELINE_CLI");
        let executable = baseline
            .as_deref()
            .map_or_else(|| Path::new(env!("CARGO_BIN_EXE_openshell")), Path::new);
        let mut command = Command::new(executable);
        command.args([
            "--gateway",
            "test-gateway",
            "--gateway-endpoint",
            &self.endpoint,
            "--workspace",
            "default",
            "--color",
            "never",
            "sandbox",
            "exec",
            "--name",
            "test-sandbox",
        ]);
        command
            .args(["--no-tty", "--no-login-shell", "--", "test-command"])
            .env("XDG_CONFIG_HOME", self.config.path())
            .env(
                "OPENSHELL_SYSTEM_GATEWAY_DIR",
                self.config.path().join("system"),
            )
            .env_remove("OPENSHELL_GATEWAY")
            .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
            .env_remove("OPENSHELL_GATEWAY_INSECURE")
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    fn spawn(&self) -> Child {
        self.command().spawn().unwrap()
    }

    fn assert_one_stream(&self) {
        let calls = self.calls.lock().unwrap();
        assert_eq!(calls.lookups, 1);
        assert_eq!(calls.starts.len(), 1, "a command must not be relaunched");
        assert_eq!(calls.unary, 0, "test input must select streaming exec");
    }
}

async fn finish(child: Child) -> Output {
    timeout(DEADLINE, child.wait_with_output())
        .await
        .expect("CLI did not terminate before the deadline")
        .unwrap()
}

async fn send_input(child: &mut Child, input: &[u8]) {
    let mut stdin = child.stdin.take().unwrap();
    // An oversized input or failed relay may close the pipe before all bytes
    // are written. The subprocess status and RPC observations decide success.
    let _ = timeout(DEADLINE, stdin.write_all(input))
        .await
        .expect("stdin write timed out");
}

#[tokio::test]
async fn default_open_pipe_exchanges_input_after_grace_and_closes_cleanly() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    let mut child = gateway.spawn();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    for request in ["before grace\n", "after grace\n"] {
        stdin.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        timeout(DEADLINE, stdout.read_line(&mut response))
            .await
            .expect("default exec must respond before stdin EOF")
            .unwrap();
        assert_eq!(response, request);
    }
    drop(stdin);
    let mut final_stdout = String::new();
    timeout(DEADLINE, stdout.read_to_string(&mut final_stdout))
        .await
        .unwrap()
        .unwrap();
    let output = finish(child).await;
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(final_stdout, "after-eof\n");
    assert_eq!(output.stderr, b"remote-stderr\n");
    gateway.assert_one_stream();
}

#[tokio::test]
async fn default_remote_exit_does_not_wait_for_idle_open_stdin() {
    let gateway = TestGateway::start(Scenario::EarlyExit).await;
    let mut child = gateway.spawn();
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"before-exit\n");
    assert!(output.stderr.is_empty());
    gateway.assert_one_stream();
    drop(held_open);
}

#[tokio::test]
async fn default_open_pipe_checks_trailer_error_after_exit() {
    let gateway = TestGateway::start(Scenario::ErrorAfterExit).await;
    let mut child = gateway.spawn();
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    gateway.assert_one_stream();
    assert!(
        !output.status.success(),
        "Exit must not hide a failing trailer"
    );
    assert_eq!(output.stdout, b"before-exit\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("failure after exit"));
    drop(held_open);
}

#[tokio::test]
async fn default_large_finite_input_checks_trailer_error_after_exit() {
    let gateway = TestGateway::start(Scenario::ErrorAfterInput).await;
    // All bytes and EOF are available before launch, so collection need not
    // wait for a pipe writer. Metadata pushes this request above 1 MiB and
    // selects streaming exec even when input finishes within the grace period.
    let input_size = 1024 * 1024;
    let input_path = gateway.config.path().join("stdin");
    std::fs::write(&input_path, vec![b'x'; input_size]).unwrap();
    let child = gateway
        .command()
        .stdin(Stdio::from(std::fs::File::open(input_path).unwrap()))
        .spawn()
        .unwrap();
    let output = finish(child).await;
    gateway.assert_one_stream();
    assert_eq!(gateway.calls.lock().unwrap().input_bytes, input_size);
    assert!(
        !output.status.success(),
        "Exit must not hide a failing trailer"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("failure after exit"));
}

#[tokio::test]
async fn default_open_pipe_overflow_warns_after_forwarding_prefix() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    let mut child = gateway.spawn();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"prefix\n")
        .await
        .unwrap();
    let mut response = String::new();
    timeout(DEADLINE, stdout.read_line(&mut response))
        .await
        .expect("prefix must reach the command before sending overflow")
        .unwrap();
    assert_eq!(response, "prefix\n");
    // Drain echo output concurrently so stdout backpressure cannot prevent
    // the input writer from reaching the cumulative prefix-and-remainder cap.
    let drain = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.unwrap();
    });
    send_input(&mut child, &vec![b'x'; STDIN_LIMIT]).await;
    let output = finish(child).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("streamed stdin exceeds the 4 MiB limit"),
        "{stderr}"
    );
    assert!(stderr.contains("partial input"), "{stderr}");
    timeout(DEADLINE, drain).await.unwrap().unwrap();
    gateway.assert_one_stream();
    assert!(gateway.calls.lock().unwrap().input_bytes <= STDIN_LIMIT);
}
