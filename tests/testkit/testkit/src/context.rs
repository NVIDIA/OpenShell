// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-test context: the SDK client, the run ID, and the resources to clean up.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use openshell_sdk::raw::{AuthedGrpcClient, proto};
use openshell_sdk::{
    DeleteOptions, ExecOptions, ListOptions, OpenShellClient, SandboxPhase, SandboxRef,
    SandboxRestartPolicy, SandboxSpec, SdkError, WorkspaceScopedClient,
};
use rand::Rng;

use crate::cli::{Cli, CliOutput};
use crate::error::{Error, Result, ResultExt};
use crate::poll::{Poll, poll_until};

/// Sandbox creation includes image pulls on a cold environment.
pub const READY_TIMEOUT: Duration = Duration::from_mins(10);
pub const DELETE_TIMEOUT: Duration = Duration::from_mins(2);
pub const EXEC_TIMEOUT: Duration = Duration::from_mins(2);
/// Stopping includes stopping compute, which can take a while on some drivers.
pub const STOP_TIMEOUT: Duration = Duration::from_mins(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_mins(2);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

/// Names of sandboxes created by a test and not yet confirmed deleted.
type Registry = Arc<Mutex<BTreeSet<String>>>;

/// What a test uses to act on the system under test.
pub struct Context {
    client: WorkspaceScopedClient,
    grpc: Grpc,
    cli: Cli,
    run_id: String,
    sandboxes: Registry,
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
            sandboxes: Registry::default(),
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
            sandboxes: Arc::clone(&self.sandboxes),
            spec: SandboxSpec {
                name: Some(self.name(suffix)),
                ..SandboxSpec::default()
            },
        }
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

    /// Delete every sandbox the test created and has not deleted. Returns the
    /// cleanup failures; they are reported separately from the test result.
    ///
    /// Sandboxes are deleted concurrently, each with the full
    /// [`CLEANUP_TIMEOUT`], so a slow delete cannot use up the time for the
    /// others and cleanup takes about one timeout however many there are.
    pub(crate) async fn cleanup(&self) -> Vec<String> {
        let names: Vec<String> = lock(&self.sandboxes).iter().cloned().collect();
        let results = futures::future::join_all(names.iter().map(|name| async move {
            self.client
                .delete_sandbox(
                    name,
                    DeleteOptions {
                        allow_missing: true,
                    },
                )
                .await?;
            self.client.wait_deleted(name, CLEANUP_TIMEOUT, None).await
        }))
        .await;
        let mut failures = Vec::new();
        for (name, result) in names.iter().zip(results) {
            match result {
                Ok(()) => {
                    lock(&self.sandboxes).remove(name);
                }
                Err(error) => failures.push(format!("delete sandbox {name}: {error}")),
            }
        }
        failures
    }
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
    sandboxes: Registry,
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
        lock(&self.sandboxes).insert(name.clone());
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
            sandboxes: self.sandboxes,
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
    sandboxes: Registry,
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
        lock(&self.sandboxes).remove(&self.name);
        Ok(())
    }
}

fn lock(registry: &Registry) -> std::sync::MutexGuard<'_, BTreeSet<String>> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Short, lowercase, and DNS-label safe, so names work on every driver.
fn generate_run_id() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_dns_label_safe() {
        let id = generate_run_id();
        assert_eq!(id.len(), 8);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "{id}"
        );
    }
}
