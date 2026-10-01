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
use tokio::sync::{Notify, mpsc};
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
    Count,
    AwaitCancellation,
    ReadAfterCancellation,
    EarlyExit,
    ErrorAfterExit,
    MissingExit,
    Disconnect,
}

#[derive(Default)]
struct Calls {
    lookups: usize,
    unary: Vec<proto::ExecSandboxRequest>,
    starts: Vec<proto::ExecSandboxRequest>,
    input_bytes: usize,
    request_ended: bool,
    request_error: bool,
    response_cancelled: bool,
}

#[derive(Clone)]
struct MockGateway {
    scenario: Scenario,
    calls: Arc<Mutex<Calls>>,
    finished: Arc<Notify>,
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
            Scenario::EarlyExit => {
                let _ = output.send(Ok(exit(0))).await;
                return;
            }
            Scenario::ErrorAfterExit => {
                let _ = output.send(Ok(exit(0))).await;
                // Deliver Exit before the later failing trailer so a client that
                // stops at Exit incorrectly reports success instead of failure.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = output
                    .send(Err(Status::internal("failure after exit")))
                    .await;
                return;
            }
            Scenario::MissingExit => {
                let _ = output.send(Ok(stdout(b"incomplete\n".to_vec()))).await;
                return;
            }
            Scenario::Disconnect => {
                let _ = output
                    .send(Err(Status::unavailable("relay disconnected")))
                    .await;
                return;
            }
            Scenario::Echo | Scenario::Count | Scenario::AwaitCancellation => {}
            Scenario::ReadAfterCancellation => {
                // Delay request polling until the client has cancelled its
                // response. Tonic can then expose CANCEL as request EOF, even
                // though the CLI never queued its explicit stdin EOF marker.
                output.closed().await;
                self.calls.lock().unwrap().response_cancelled = true;
            }
        }

        loop {
            let message = tokio::select! {
                biased;
                () = output.closed(), if !matches!(self.scenario, Scenario::ReadAfterCancellation) => {
                    self.calls.lock().unwrap().response_cancelled = true;
                    return;
                }
                message = input.message() => message,
            };
            match message {
                Ok(Some(frame)) => match frame.payload {
                    Some(exec_sandbox_input::Payload::Stdin(bytes)) => {
                        self.calls.lock().unwrap().input_bytes += bytes.len();
                        if matches!(self.scenario, Scenario::Echo)
                            && output.send(Ok(stdout(bytes))).await.is_err()
                        {
                            // A failed send observes the same response drop as
                            // output.closed(), including cancellation mid-echo.
                            self.calls.lock().unwrap().response_cancelled = true;
                            return;
                        }
                    }
                    // The malformed abort frame can arrive before cancellation
                    // or be discarded by it. Neither outcome proves clean EOF.
                    None if matches!(self.scenario, Scenario::ReadAfterCancellation) => {}
                    None if matches!(self.scenario, Scenario::AwaitCancellation) => break,
                    None => return,
                    unexpected => panic!("unexpected input after start: {unexpected:?}"),
                },
                Ok(None) => {
                    // Request completion alone cannot distinguish clean stdin
                    // EOF from HTTP/2 cancellation. Observe the response too.
                    self.calls.lock().unwrap().request_ended = true;
                    break;
                }
                Err(_) => {
                    self.calls.lock().unwrap().request_error = true;
                    if matches!(self.scenario, Scenario::AwaitCancellation) {
                        break;
                    }
                    return;
                }
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
            Scenario::Count => {
                let total = self.calls.lock().unwrap().input_bytes;
                let _ = output
                    .send(Ok(stdout(format!("{total}\n").into_bytes())))
                    .await;
                let _ = output.send(Ok(exit(0))).await;
            }
            Scenario::AwaitCancellation | Scenario::ReadAfterCancellation => {
                // Keep the response open so this witness cannot be caused by
                // the mock finishing normally after an ambiguous request end.
                output.closed().await;
                self.calls.lock().unwrap().response_cancelled = true;
            }
            _ => unreachable!(),
        }
    }
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
            async fn exec_sandbox(&self, request: Request<proto::ExecSandboxRequest>) -> Result<Response<EventStream>, Status> {
                let request = request.into_inner();
                let bytes = request.stdin.clone();
                self.calls.lock().unwrap().unary.push(request);
                let (sender, receiver) = mpsc::channel(2);
                sender.send(Ok(stdout(bytes))).await.unwrap();
                sender.send(Ok(exit(0))).await.unwrap();
                Ok(Response::new(ReceiverStream::new(receiver)))
            }

            type ExecSandboxInteractiveStream = EventStream;
            async fn exec_sandbox_interactive(&self, request: Request<tonic::Streaming<proto::ExecSandboxInput>>) -> Result<Response<EventStream>, Status> {
                let (sender, receiver) = mpsc::channel(1);
                let service = self.clone();
                tokio::spawn(async move {
                    service.clone().exchange(request.into_inner(), sender).await;
                    service.finished.notify_one();
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
    finished: Arc<Notify>,
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
        let finished = Arc::new(Notify::new());
        let service = MockGateway {
            scenario,
            calls: Arc::clone(&calls),
            finished: Arc::clone(&finished),
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
            finished,
            task,
        }
    }

    fn command(&self, executable: &Path, streaming: bool) -> Command {
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
        if streaming {
            command.arg("--stream-stdin");
        }
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

    fn spawn(&self, streaming: bool) -> Child {
        self.command(Path::new(env!("CARGO_BIN_EXE_openshell")), streaming)
            .spawn()
            .unwrap()
    }

    fn assert_one_stream(&self) {
        let calls = self.calls.lock().unwrap();
        assert_eq!(calls.lookups, 1);
        assert_eq!(calls.starts.len(), 1, "a command must not be relaunched");
        assert!(
            calls.unary.is_empty(),
            "streaming mode must never use unary exec"
        );
    }

    async fn wait_for_stream_end(&self) {
        timeout(DEADLINE, self.finished.notified())
            .await
            .expect("gateway did not observe request completion or cancellation");
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
async fn streaming_exchanges_two_requests_before_eof_and_drains_final_output() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    // This override is restricted to the regression reproducer: an older CLI
    // has no --stream-stdin flag, but must still reach the same gateway lookup.
    let baseline = std::env::var_os("OPENSHELL_STREAMING_TEST_BASELINE_CLI");
    let executable = baseline
        .as_deref()
        .map_or_else(|| Path::new(env!("CARGO_BIN_EXE_openshell")), Path::new);
    let mut child = gateway
        .command(executable, baseline.is_none())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    for request in ["first request\n", "second request\n"] {
        stdin.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        let read = timeout(DEADLINE, stdout.read_line(&mut response)).await;
        if read.is_err() {
            let calls = gateway.calls.lock().unwrap();
            assert_eq!(calls.lookups, 1, "CLI did not reach the gateway");
            panic!(
                "no response before stdin EOF: {} starts, {} unary calls",
                calls.starts.len(),
                calls.unary.len()
            );
        }
        assert_eq!(
            gateway.calls.lock().unwrap().lookups,
            1,
            "CLI did not reach the gateway"
        );
        assert_ne!(read.unwrap().unwrap(), 0, "CLI ended before response");
        assert_eq!(response, request);
        assert!(
            child.try_wait().unwrap().is_none(),
            "CLI ended between exchanges"
        );
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
    assert!(gateway.calls.lock().unwrap().request_ended);
}

#[tokio::test]
async fn streaming_remote_exit_does_not_wait_for_idle_open_stdin() {
    let gateway = TestGateway::start(Scenario::EarlyExit).await;
    let mut child = gateway.spawn(true);
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    gateway.assert_one_stream();
    assert!(!gateway.calls.lock().unwrap().request_ended);
    drop(held_open);
}

#[tokio::test]
async fn default_open_pipe_exchanges_input_after_grace_and_closes_cleanly() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    let mut child = gateway.spawn(false);
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
    assert!(gateway.calls.lock().unwrap().request_ended);
}

#[tokio::test]
async fn default_open_pipe_overflow_cancels_after_forwarding_prefix() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    let mut child = gateway.spawn(false);
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
    // Drain echo output concurrently so stdout backpressure does not prevent
    // the input writer from reaching the cap and cancelling the response.
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
    gateway.wait_for_stream_end().await;
    gateway.assert_one_stream();
    let calls = gateway.calls.lock().unwrap();
    assert!(calls.input_bytes <= STDIN_LIMIT);
    assert!(calls.response_cancelled);
}

#[tokio::test]
async fn streaming_trailer_error_after_exit_is_not_success() {
    let gateway = TestGateway::start(Scenario::ErrorAfterExit).await;
    let mut child = gateway.spawn(true);
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failure after exit"));
    gateway.assert_one_stream();
    drop(held_open);
}

#[tokio::test]
async fn default_large_pipe_checks_trailer_error_after_exit() {
    let gateway = TestGateway::start(Scenario::ErrorAfterExit).await;
    let baseline = std::env::var_os("OPENSHELL_STREAMING_TEST_BASELINE_CLI");
    let executable = baseline
        .as_deref()
        .map_or_else(|| Path::new(env!("CARGO_BIN_EXE_openshell")), Path::new);
    let mut child = gateway.command(executable, false).spawn().unwrap();
    // The encoded request includes metadata, so a 1 MiB payload selects the
    // existing streaming transport even without the new command-line flag.
    send_input(&mut child, &vec![b'x'; 1024 * 1024]).await;
    let output = finish(child).await;
    gateway.assert_one_stream();
    assert!(
        !output.status.success(),
        "Exit must not hide a failing trailer"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("failure after exit"));
}

#[tokio::test]
async fn streaming_missing_exit_is_not_success() {
    let gateway = TestGateway::start(Scenario::MissingExit).await;
    let mut child = gateway.spawn(true);
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    assert!(!output.status.success());
    assert_eq!(output.stdout, b"incomplete\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("exit status"));
    gateway.assert_one_stream();
    drop(held_open);
}

#[tokio::test]
async fn streaming_disconnect_does_not_start_another_command() {
    let gateway = TestGateway::start(Scenario::Disconnect).await;
    let mut child = gateway.spawn(true);
    let held_open = child.stdin.take().unwrap();
    let output = finish(child).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr
        .replace(['│', '×'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(normalized.contains("relay disconnected"), "{stderr}");
    gateway.assert_one_stream();
    drop(held_open);
}

#[tokio::test]
async fn streaming_accepts_exact_input_limit() {
    let gateway = TestGateway::start(Scenario::Count).await;
    let mut child = gateway.spawn(true);
    send_input(&mut child, &vec![b'x'; STDIN_LIMIT]).await;
    let output = finish(child).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, format!("{STDIN_LIMIT}\n").as_bytes());
    gateway.assert_one_stream();
    assert!(gateway.calls.lock().unwrap().request_ended);
}

#[tokio::test]
async fn streaming_rejects_excess_input_and_cancels_response() {
    let gateway = TestGateway::start(Scenario::AwaitCancellation).await;
    let mut child = gateway.spawn(true);
    send_input(&mut child, &vec![b'x'; STDIN_LIMIT + 1]).await;
    let output = finish(child).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("streamed stdin exceeds the 4 MiB limit"),
        "{stderr}"
    );
    assert!(stderr.contains("partial input"), "{stderr}");
    gateway.wait_for_stream_end().await;
    gateway.assert_one_stream();
    let calls = gateway.calls.lock().unwrap();
    assert!(calls.input_bytes <= STDIN_LIMIT);
    assert!(calls.response_cancelled);
}

#[tokio::test]
async fn streaming_reports_unreadable_stdin_and_cancels_response() {
    let gateway = TestGateway::start(Scenario::AwaitCancellation).await;
    let input = std::fs::File::open(gateway.config.path()).unwrap();
    let child = gateway
        .command(Path::new(env!("CARGO_BIN_EXE_openshell")), true)
        .stdin(Stdio::from(input))
        .spawn()
        .unwrap();
    let output = finish(child).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Is a directory"), "{stderr}");
    gateway.wait_for_stream_end().await;
    gateway.assert_one_stream();
    let calls = gateway.calls.lock().unwrap();
    assert_eq!(calls.input_bytes, 0);
    assert!(calls.response_cancelled);
}

#[tokio::test]
async fn streaming_cancelled_request_ends_after_delayed_poll() {
    let gateway = TestGateway::start(Scenario::ReadAfterCancellation).await;
    let input = std::fs::File::open(gateway.config.path()).unwrap();
    let child = gateway
        .command(Path::new(env!("CARGO_BIN_EXE_openshell")), true)
        .stdin(Stdio::from(input))
        .spawn()
        .unwrap();
    let output = finish(child).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Is a directory"));
    gateway.wait_for_stream_end().await;
    gateway.assert_one_stream();
    let calls = gateway.calls.lock().unwrap();
    assert_eq!(calls.input_bytes, 0);
    assert!(calls.response_cancelled);
    assert!(
        calls.request_ended || calls.request_error,
        "cancellation must terminate the request, whether as EOF or a transport error"
    );
}

#[tokio::test]
async fn cancelled_tonic_request_can_decode_as_end_of_input() {
    struct NoFrames;
    impl tonic::codec::Decoder for NoFrames {
        type Item = ();
        type Error = Status;

        fn decode(&mut self, _: &mut tonic::codec::DecodeBuf<'_>) -> Result<Option<()>, Status> {
            Err(Status::internal("the cancelled body contains no message"))
        }
    }

    // Inject cancellation at the decoder boundary rather than relying on the
    // HTTP/2 transport to choose the same terminal outcome on every platform.
    let cancelled: Result<hyper::body::Frame<bytes::Bytes>, Status> =
        Err(Status::cancelled("synthetic request cancellation"));
    let body = http_body_util::StreamBody::new(futures::stream::iter([cancelled]));
    let mut request = tonic::Streaming::new_request(NoFrames, body, None, None);
    assert!(request.message().await.unwrap().is_none());

    let unavailable: Result<hyper::body::Frame<bytes::Bytes>, Status> =
        Err(Status::unavailable("synthetic transport failure"));
    let body = http_body_util::StreamBody::new(futures::stream::iter([unavailable]));
    let mut request = tonic::Streaming::new_request(NoFrames, body, None, None);
    assert_eq!(
        request.message().await.unwrap_err().code(),
        tonic::Code::Unavailable,
    );
}

#[tokio::test]
async fn default_small_pipe_retains_unary_exec() {
    let gateway = TestGateway::start(Scenario::Echo).await;
    let mut child = gateway.spawn(false);
    send_input(&mut child, b"finite input").await;
    let output = finish(child).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"finite input");
    let calls = gateway.calls.lock().unwrap();
    assert_eq!(calls.unary.len(), 1);
    assert!(calls.starts.is_empty());
    assert!(!calls.unary[0].tty);
}

#[tokio::test]
async fn default_large_finite_pipe_retains_streaming_transport() {
    let gateway = TestGateway::start(Scenario::Count).await;
    let mut child = gateway.spawn(false);
    send_input(&mut child, &vec![b'x'; STDIN_LIMIT]).await;
    let output = finish(child).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, format!("{STDIN_LIMIT}\n").as_bytes());
    gateway.assert_one_stream();
    assert!(gateway.calls.lock().unwrap().request_ended);
}

#[tokio::test]
async fn default_oversized_pipe_is_rejected_or_cancels_after_grace() {
    let gateway = TestGateway::start(Scenario::AwaitCancellation).await;
    let mut child = gateway.spawn(false);
    send_input(&mut child, &vec![b'x'; STDIN_LIMIT + 1]).await;
    let output = finish(child).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let started = !gateway.calls.lock().unwrap().starts.is_empty();
    // Scheduler speed determines whether the cap is reached during the grace
    // period. Both rejection before launch and bounded cancellation are valid.
    if started {
        assert!(
            stderr.contains("streamed stdin exceeds the 4 MiB limit"),
            "{stderr}"
        );
        assert!(stderr.contains("partial input"), "{stderr}");
        gateway.wait_for_stream_end().await;
        gateway.assert_one_stream();
    } else {
        assert!(
            stderr.contains("piped stdin exceeds the 4 MiB limit"),
            "{stderr}"
        );
    }
    let calls = gateway.calls.lock().unwrap();
    assert_eq!(calls.lookups, 1);
    assert!(calls.unary.is_empty());
    assert!(calls.input_bytes <= STDIN_LIMIT);
    assert!(!started || calls.response_cancelled);
}
