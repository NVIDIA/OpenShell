// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-test context: the SDK client, the run ID, and the resources to clean up.

use std::time::Duration;

use openshell_sdk::raw::{AuthedGrpcClient, proto};
use openshell_sdk::{
    DeleteOptions, ExecOptions, ListOptions, OpenShellClient, SandboxPhase, SandboxRef,
    SandboxRestartPolicy, SandboxSpec, SdkError, WorkspaceScopedClient,
};
use rand::Rng;

use crate::cleanup::{CLEANUP_TIMEOUT, Cleanup};
use crate::cli::{Cli, CliOutput};
use crate::error::{Error, Result, ResultExt};
use crate::poll::{Poll, poll_until};

/// Sandbox creation includes image pulls on a cold environment.
pub const READY_TIMEOUT: Duration = Duration::from_mins(10);
pub const DELETE_TIMEOUT: Duration = Duration::from_mins(2);
pub const EXEC_TIMEOUT: Duration = Duration::from_mins(2);
/// Stopping includes stopping compute, which can take a while on some drivers.
pub const STOP_TIMEOUT: Duration = Duration::from_mins(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

/// What a test uses to act on the system under test.
pub struct Context {
    client: WorkspaceScopedClient,
    grpc: Grpc,
    cli: Cli,
    run_id: String,
    cleanup: Cleanup,
}

impl Context {
    pub(crate) fn new(client: &OpenShellClient, workspace: &str, cli: Cli) -> Self {
        Self {
            client: client.workspace(workspace),
            grpc: Grpc {
                client: client.clone(),
                workspace: workspace.to_string(),
            },
            cli,
            run_id: generate_run_id(),
            cleanup: Cleanup::default(),
        }
    }

    /// Run the `openshell` CLI against the test's gateway and workspace.
    /// A non-zero exit is returned, not raised.
    pub async fn cli<I, S>(&self, args: I) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.cli.run(args).await
    }

    /// Like [`Context::cli`], with `dir` as the working directory.
    pub async fn cli_in<I, S>(&self, dir: &std::path::Path, args: I) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.cli.run_in(Some(dir), args).await
    }

    /// Like [`Context::cli`], with extra environment variables for the CLI.
    /// Pass secrets this way rather than as arguments: values are not
    /// included in the reported command or in errors.
    pub async fn cli_with_env<I, S>(&self, env: &[(&str, &str)], args: I) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.cli.run_with_env(None, env, args).await
    }

    /// The CLI that [`Context::cli`] runs, for code that can't borrow the
    /// context, such as a cleanup hook.
    pub fn cli_handle(&self) -> Cli {
        self.cli.clone()
    }

    /// The ID unique to this test run, used in resource names.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The SDK client, for operations testkit does not wrap.
    pub fn client(&self) -> &WorkspaceScopedClient {
        &self.client
    }

    /// A resource name unique to this run: `test-<run-id>-<suffix>`.
    pub fn name(&self, suffix: &str) -> String {
        format!("test-{}-{suffix}", self.run_id)
    }

    /// Start describing a sandbox named `cx.name(suffix)`.
    pub fn sandbox(&self, suffix: &str) -> SandboxBuilder {
        SandboxBuilder {
            client: self.client.clone(),
            grpc: self.grpc.clone(),
            policy: None,
            cleanup: self.cleanup.clone(),
            spec: SandboxSpec {
                name: Some(self.name(suffix)),
                ..SandboxSpec::default()
            },
        }
    }

    /// Track a sandbox the test is about to create through the CLI, so cleanup
    /// deletes it even if the test fails after the gateway accepted the create.
    /// Call this before the CLI command; use [`Context::adopt`] afterwards.
    ///
    /// Cleanup deletes the sandbox and waits until it is gone, at the point
    /// in the cleanup order where it was first tracked. Tracking a sandbox
    /// again, for example by adopting it, doesn't move it.
    pub fn track(&self, name: &str) {
        track_sandbox(&self.cleanup, &self.client, name);
    }

    /// Run `hook` after the test body, whether the body passes, fails, or
    /// panics. Use it to remove what testkit doesn't track, such as
    /// providers, profiles, or images. `name` says what the hook does, for
    /// reporting a failure.
    ///
    /// Hooks run one at a time, last registered first, after the body and
    /// before the test reports. Sandboxes from [`Context::sandbox`] and
    /// [`Context::track`] are cleaned up the same way, so a hook registered
    /// before a sandbox is created runs after the sandbox is deleted. Each
    /// hook has [`CLEANUP_TIMEOUT`]. A hook that fails, panics, or times out
    /// is reported and the remaining hooks still run; it fails a test whose
    /// body passed.
    ///
    /// `provider delete` succeeds for a missing provider, so this registers
    /// the hook before the create. It then also covers a create the gateway
    /// applied but the CLI reported as failed.
    ///
    /// ```ignore
    /// let cli = cx.cli_handle();
    /// let provider = cx.name("provider");
    /// let name = provider.clone();
    /// cx.on_cleanup(format!("delete provider {provider}"), async move || {
    ///     cli.run(["provider", "delete", &name]).await?.success()?;
    ///     Ok(())
    /// });
    /// cx.cli(["provider", "create", "--name", &provider /* ... */])
    ///     .await?
    ///     .success()?;
    /// ```
    pub fn on_cleanup<F, Fut>(&self, name: impl Into<String>, hook: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        self.cleanup.push(name, hook);
    }

    /// A handle to a sandbox created outside the builder, e.g. by the CLI.
    /// It is tracked for cleanup like a built one.
    pub async fn adopt(&self, name: &str) -> Result<Sandbox> {
        self.track(name);
        let found = self
            .client
            .get_sandbox(name)
            .await
            .context(format!("get sandbox {name}"))?;
        Ok(Sandbox {
            client: self.client.clone(),
            grpc: self.grpc.clone(),
            cleanup: self.cleanup.clone(),
            name: name.to_string(),
            id: found.id,
        })
    }

    /// Fail unless the sandbox is gone from both get and list.
    pub async fn expect_absent(&self, sandbox: &Sandbox) -> Result {
        let name = sandbox.name();
        match self.client.get_sandbox(name).await {
            Err(SdkError::NotFound { .. }) => {}
            Err(error) => return Err(Error::from(error).context(format!("get sandbox {name}"))),
            Ok(found) => {
                return Err(Error::msg(format!(
                    "sandbox {name} still exists (id {}, phase {:?})",
                    found.id, found.phase
                )));
            }
        }
        let listed = self
            .client
            .list_all_sandboxes(ListOptions::default())
            .await
            .context("list sandboxes")?;
        crate::ensure!(
            !listed.iter().any(|entry| entry.name == name),
            "sandbox {name} is absent from get but still listed"
        );
        Ok(())
    }

    /// Fail unless the gateway runs exactly one compute driver, `name`, as
    /// gateway info reports it. Driver suites check this first, so a suite
    /// pointed at another driver's gateway fails instead of testing it.
    pub async fn expect_compute_driver(&self, name: &str) -> Result {
        let info = self
            .grpc
            .client()
            .await?
            .get_gateway_info(proto::GetGatewayInfoRequest {})
            .await
            .map_err(|status| Error::from_error(&status))
            .context("get gateway info")?
            .into_inner();
        let drivers: Vec<(&str, &str)> = info
            .compute_drivers
            .iter()
            .map(|driver| {
                let reported = driver
                    .capabilities
                    .as_ref()
                    .map_or("", |capabilities| capabilities.driver_name.as_str());
                (driver.name.as_str(), reported)
            })
            .collect();
        crate::ensure!(
            matches!(drivers.as_slice(), [(configured, reported)] if *configured == name && *reported == name),
            "the gateway reports compute drivers (name, driver name) {drivers:?}; expected only {name}"
        );
        Ok(())
    }

    /// Fail unless `list` shows the sandbox in `phase`.
    pub async fn expect_listed(&self, sandbox: &Sandbox, phase: SandboxPhase) -> Result {
        let name = sandbox.name();
        let listed = self
            .client
            .list_all_sandboxes(ListOptions::default())
            .await
            .context("list sandboxes")?;
        let entry = listed.iter().find(|entry| entry.name == name);
        crate::ensure!(entry.is_some(), "sandbox {name} is not listed");
        let entry = entry.expect("checked above");
        crate::ensure!(
            entry.phase == phase,
            "sandbox {name} is listed in phase {:?}; expected {phase:?}",
            entry.phase
        );
        Ok(())
    }

    /// Run the cleanup hooks, including deleting the sandboxes the test
    /// created and has not deleted. Returns the cleanup failures; they are
    /// reported separately from the test result.
    pub(crate) async fn cleanup(&self) -> Vec<String> {
        self.cleanup.run(CLEANUP_TIMEOUT).await
    }
}

/// Register the cleanup hook that deletes sandbox `name`, unless it is
/// already tracked.
fn track_sandbox(cleanup: &Cleanup, client: &WorkspaceScopedClient, name: &str) {
    let client = client.clone();
    let owned = name.to_string();
    // The timeout wraps the whole hook, not just the wait, so a gateway that
    // never answers the delete cannot hang cleanup.
    cleanup.push_keyed(name, format!("delete sandbox {name}"), async move || {
        client
            .delete_sandbox(
                &owned,
                DeleteOptions {
                    allow_missing: true,
                },
            )
            .await?;
        client.wait_deleted(&owned, CLEANUP_TIMEOUT, None).await?;
        Ok(())
    });
}

/// The generated gRPC client, for public API the SDK does not wrap yet.
#[derive(Clone)]
struct Grpc {
    client: OpenShellClient,
    workspace: String,
}

impl Grpc {
    async fn client(&self) -> Result<AuthedGrpcClient> {
        Ok(self.client.raw_grpc_fresh().await?)
    }

    fn scope(&self) -> Option<openshell_sdk::raw::proto::datamodel::v1::WorkspaceSelector> {
        Some(proto::workspace_selector(&self.workspace))
    }
}

/// A sandbox to create.
pub struct SandboxBuilder {
    client: WorkspaceScopedClient,
    grpc: Grpc,
    policy: Option<proto::SandboxPolicy>,
    cleanup: Cleanup,
    spec: SandboxSpec,
}

impl SandboxBuilder {
    /// The sandbox's main command. Empty selects the gateway's default.
    #[must_use]
    pub fn command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.spec.command = command.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn restart_policy(mut self, policy: SandboxRestartPolicy) -> Self {
        self.spec.restart_policy = policy;
        self
    }

    /// Create the sandbox with this policy instead of the gateway's default.
    #[must_use]
    pub fn policy(mut self, policy: proto::SandboxPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Full access to the spec for fields without a builder method.
    #[must_use]
    pub fn spec(mut self, update: impl FnOnce(&mut SandboxSpec)) -> Self {
        update(&mut self.spec);
        self
    }

    /// Create the sandbox. It is tracked for cleanup before the request is
    /// sent, so a create that fails after the gateway accepted it is still
    /// cleaned up.
    pub async fn create(self) -> Result<Sandbox> {
        let name = self.spec.name.clone().unwrap_or_default();
        track_sandbox(&self.cleanup, &self.client, &name);
        let id = match self.policy {
            None => {
                self.client
                    .create_sandbox(self.spec)
                    .await
                    .context(format!("create sandbox {name}"))?
                    .id
            }
            // The SDK's spec has no policy field, so create through gRPC.
            Some(policy) => {
                crate::ensure!(
                    self.spec.image.is_none()
                        && self.spec.environment.is_empty()
                        && self.spec.providers.is_empty()
                        && !self.spec.gpu
                        && self.spec.service_exposures.is_empty(),
                    "testkit creates a sandbox with a policy from its name, labels, command, restart policy, and policy only"
                );
                let request = proto::CreateSandboxRequest {
                    name: name.clone(),
                    labels: self.spec.labels,
                    workspace_scope: self.grpc.scope(),
                    spec: Some(proto::SandboxSpec {
                        command: self.spec.command,
                        tty: self.spec.tty,
                        policy: Some(policy),
                        restart_policy: restart_policy(self.spec.restart_policy) as i32,
                        ..proto::SandboxSpec::default()
                    }),
                    ..proto::CreateSandboxRequest::default()
                };
                self.grpc
                    .client()
                    .await?
                    .create_sandbox(request)
                    .await
                    .map_err(|status| Error::from_error(&status))
                    .context(format!("create sandbox {name}"))?;
                self.client
                    .get_sandbox(&name)
                    .await
                    .context(format!("get sandbox {name}"))?
                    .id
            }
        };
        Ok(Sandbox {
            client: self.client,
            grpc: self.grpc,
            cleanup: self.cleanup,
            name,
            id,
        })
    }
}

const fn restart_policy(policy: SandboxRestartPolicy) -> proto::SandboxRestartPolicy {
    match policy {
        SandboxRestartPolicy::Never => proto::SandboxRestartPolicy::Never,
        SandboxRestartPolicy::OnFailure => proto::SandboxRestartPolicy::OnFailure,
        SandboxRestartPolicy::Always => proto::SandboxRestartPolicy::Always,
    }
}

/// A sandbox created by the test.
pub struct Sandbox {
    client: WorkspaceScopedClient,
    grpc: Grpc,
    cleanup: Cleanup,
    name: String,
    id: String,
}

/// The buffered output of an exec.
#[derive(Debug)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Sandbox {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Wait until the sandbox is Ready. A sandbox that completes or fails
    /// instead is an error.
    pub async fn wait_ready(&self) -> Result<SandboxRef> {
        let snapshot = self
            .client
            .wait_ready(&self.name, READY_TIMEOUT)
            .await
            .context(format!("wait for sandbox {} to be ready", self.name))?;
        crate::ensure!(
            snapshot.phase == SandboxPhase::Ready,
            "sandbox {} reached phase {:?}; expected Ready",
            self.name,
            snapshot.phase
        );
        Ok(snapshot)
    }

    /// Wait until the main process has finished: the sandbox is Completed or
    /// in Error. Returns that snapshot; the test decides which outcome it
    /// expects. Includes provisioning, so it uses the ready timeout.
    pub async fn wait_finished(&self) -> Result<SandboxRef> {
        poll_until(
            &format!("sandbox {} to finish", self.name),
            READY_TIMEOUT,
            STATUS_INTERVAL,
            async || {
                let snapshot = self.get().await?;
                Ok(match snapshot.phase {
                    SandboxPhase::Completed | SandboxPhase::Error => Poll::Ready(snapshot),
                    phase => Poll::Pending(format!("phase {phase:?}")),
                })
            },
        )
        .await
    }

    /// Stop the sandbox and wait until it is Stopped.
    pub async fn stop(&self) -> Result<SandboxRef> {
        self.client
            .stop_sandbox(&self.name)
            .await
            .context(format!("stop sandbox {}", self.name))?;
        self.wait_phase(SandboxPhase::Stopped, STOP_TIMEOUT).await
    }

    /// Start the sandbox and wait until it is Ready again.
    pub async fn start(&self) -> Result<SandboxRef> {
        self.client
            .start_sandbox(&self.name)
            .await
            .context(format!("start sandbox {}", self.name))?;
        self.wait_ready().await
    }

    /// Wait until the sandbox reaches `phase`.
    pub async fn wait_phase(&self, phase: SandboxPhase, timeout: Duration) -> Result<SandboxRef> {
        poll_until(
            &format!("sandbox {} to be {phase:?}", self.name),
            timeout,
            STATUS_INTERVAL,
            async || {
                let snapshot = self.get().await?;
                Ok(if snapshot.phase == phase {
                    Poll::Ready(snapshot)
                } else {
                    Poll::Pending(format!("phase {:?}", snapshot.phase))
                })
            },
        )
        .await
    }

    /// Set a sandbox-scoped setting.
    pub async fn set_setting(&self, key: &str, value: proto::setting_value::Value) -> Result {
        let request = proto::UpdateConfigRequest {
            sandbox: self.name.clone(),
            workspace_scope: self.grpc.scope(),
            setting_key: key.to_string(),
            setting_value: Some(proto::SettingValue { value: Some(value) }),
            ..proto::UpdateConfigRequest::default()
        };
        self.grpc
            .client()
            .await?
            .update_config(request)
            .await
            .map_err(|status| Error::from_error(&status))
            .context(format!("set {key} on sandbox {}", self.name))?;
        Ok(())
    }

    /// The sandbox's effective policy and settings.
    pub async fn config(&self) -> Result<proto::GetSandboxConfigResponse> {
        let request = proto::GetSandboxConfigRequest {
            name: self.name.clone(),
            workspace_scope: self.grpc.scope(),
        };
        Ok(self
            .grpc
            .client()
            .await?
            .get_sandbox_config(request)
            .await
            .map_err(|status| Error::from_error(&status))
            .context(format!("get config of sandbox {}", self.name))?
            .into_inner())
    }

    /// The sandbox's draft policy chunks, all statuses.
    pub async fn draft_policy(&self) -> Result<proto::GetDraftPolicyResponse> {
        let request = proto::GetDraftPolicyRequest {
            sandbox: self.name.clone(),
            workspace_scope: self.grpc.scope(),
            status_filter: String::new(),
        };
        Ok(self
            .grpc
            .client()
            .await?
            .get_draft_policy(request)
            .await
            .map_err(|status| Error::from_error(&status))
            .context(format!("get draft policy of sandbox {}", self.name))?
            .into_inner())
    }

    /// The sandbox's current state.
    pub async fn get(&self) -> Result<SandboxRef> {
        self.client
            .get_sandbox(&self.name)
            .await
            .context(format!("get sandbox {}", self.name))
    }

    /// Run a command in the sandbox and buffer its output.
    pub async fn exec<I, S>(&self, command: I) -> Result<ExecOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command: Vec<String> = command.into_iter().map(Into::into).collect();
        let options = ExecOptions {
            timeout: Some(EXEC_TIMEOUT),
            ..ExecOptions::default()
        };
        let result = self
            .client
            .exec(&self.name, &command, options)
            .await
            .context(format!("exec {command:?} in sandbox {}", self.name))?;
        Ok(ExecOutput {
            exit_code: result.exit_code,
            stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        })
    }

    /// Delete the sandbox and wait until it is gone.
    pub async fn delete(&self) -> Result {
        self.client
            .delete_sandbox(&self.name, DeleteOptions::default())
            .await
            .context(format!("delete sandbox {}", self.name))?;
        self.client
            .wait_deleted(&self.name, DELETE_TIMEOUT, Some(&self.id))
            .await
            .context(format!("wait for sandbox {} to be deleted", self.name))?;
        self.cleanup.remove(&self.name);
        Ok(())
    }
}

#[cfg(test)]
impl Context {
    /// A context for a gateway that isn't running, so gateway calls fail.
    pub(crate) fn unconnected() -> Self {
        const ENDPOINT: &str = "http://127.0.0.1:1";
        let channel = tonic::transport::Channel::from_static(ENDPOINT).connect_lazy();
        let interceptor =
            openshell_sdk::EdgeAuthInterceptor::new(None, None).expect("no-op interceptor");
        let client = OpenShellClient::from_parts(channel, interceptor);
        let gateway =
            crate::gateway::Gateway::from_endpoint(ENDPOINT.to_string(), "default".to_string());
        Self::new(&client, "default", Cli::from_env(&gateway))
    }
}

/// Short, lowercase, and DNS-label safe, so names work on every driver.
fn generate_run_id() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}
