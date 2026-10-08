// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build pushed configuration parts for one session.

use std::time::{Duration, Instant};

use openshell_core::proto::{
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse, Sandbox,
};
use tonic::Status;

use super::session::BuiltPart;
use crate::ServerState;
use crate::gateway_metrics::{BuildTrigger, ConfigPart, record_config_build};
use crate::grpc::policy::config_snapshot::{
    build_provider_environment, build_sandbox_config, is_configuration_error,
    load_sandbox_config_inputs, not_admitted_sandbox_config,
};
use crate::persistence::ObjectWorkspace as _;

/// Bound on loading inputs and building the policy and settings part.
pub const SANDBOX_CONFIG_BUILD_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on building the provider environment, which may call credential
/// backends.
pub const PROVIDER_ENVIRONMENT_BUILD_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest encoded part the gateway pushes. Supervisors decode at most 4 MiB
/// per message, and one update may carry both parts.
pub const MAX_PART_BYTES: usize = 2 * 1024 * 1024 - 64 * 1024;

/// Parts built from one read of the gateway's state.
#[derive(Debug)]
pub struct BuiltParts {
    pub sandbox_config: BuiltPart<GetSandboxConfigResponse>,
    pub provider_environment: Option<BuiltPart<GetSandboxProviderEnvironmentResponse>>,
    /// Workspace of the sandbox, for change scoping.
    pub workspace: String,
    /// Object ids of the providers the build read, for change scoping.
    /// `None` when the stored configuration could not be read as valid.
    pub provider_ids: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum BuildError {
    /// The sandbox no longer exists; its session is ending.
    SandboxGone,
    /// A read, credential resolution, or bound failed. Retry later.
    Failed(Status),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SandboxGone => f.write_str("sandbox no longer exists"),
            Self::Failed(status) => write!(f, "{}: {}", status.code(), status.message()),
        }
    }
}

fn bounded<T>(part: ConfigPart, message: T) -> Result<T, BuildError>
where
    T: prost::Message,
{
    let size = message.encoded_len();
    if size > MAX_PART_BYTES {
        return Err(BuildError::Failed(Status::resource_exhausted(format!(
            "{} part is {size} bytes, above the {MAX_PART_BYTES}-byte push limit",
            part.label()
        ))));
    }
    Ok(message)
}

async fn timed<T>(
    timeout: Duration,
    what: &str,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| Status::deadline_exceeded(format!("{what} took longer than {timeout:?}")))?
}

/// Build the policy part for `sandbox_id` and, when `wants_provider` says so,
/// the provider environment from the same load.
pub async fn build_parts(
    state: &ServerState,
    sandbox_id: &str,
    wants_provider: impl FnOnce(&BuiltPart<GetSandboxConfigResponse>) -> bool,
) -> Result<BuiltParts, BuildError> {
    let started = Instant::now();
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| BuildError::Failed(Status::internal(format!("fetch sandbox failed: {e}"))))?
        .ok_or(BuildError::SandboxGone)?;
    let workspace = sandbox.object_workspace().to_string();

    let loaded = timed(SANDBOX_CONFIG_BUILD_TIMEOUT, "configuration build", async {
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        let config = build_sandbox_config(state, &inputs).await?;
        Ok((inputs, config))
    })
    .await;
    let (inputs, config) = match loaded {
        Ok((inputs, config)) => (Some(inputs), config),
        // As with polling, invalid stored configuration is delivered as a
        // rejected snapshot so the supervisor applies its failure posture.
        Err(error) if is_configuration_error(&error) => {
            (None, not_admitted_sandbox_config(&sandbox, &error))
        }
        Err(error) => {
            record_config_build(
                ConfigPart::SandboxConfig,
                BuildTrigger::Push,
                false,
                started.elapsed(),
            );
            return Err(BuildError::Failed(error));
        }
    };
    record_config_build(
        ConfigPart::SandboxConfig,
        BuildTrigger::Push,
        true,
        started.elapsed(),
    );
    let sandbox_config = BuiltPart::sandbox_config(bounded(ConfigPart::SandboxConfig, config)?);

    let provider_ids = inputs
        .as_ref()
        .map(|inputs| inputs.provider_ids().map(ToString::to_string).collect());
    let provider_environment = match inputs {
        Some(inputs)
            if sandbox_config.message.configuration_admitted && wants_provider(&sandbox_config) =>
        {
            let started = Instant::now();
            let environment = timed(
                PROVIDER_ENVIRONMENT_BUILD_TIMEOUT,
                "provider environment build",
                build_provider_environment(state, &inputs, true),
            )
            .await;
            record_config_build(
                ConfigPart::ProviderEnvironment,
                BuildTrigger::Push,
                environment.is_ok(),
                started.elapsed(),
            );
            let environment = environment.map_err(BuildError::Failed)?;
            Some(BuiltPart::provider_environment(bounded(
                ConfigPart::ProviderEnvironment,
                environment,
            )?))
        }
        _ => None,
    };

    Ok(BuiltParts {
        sandbox_config,
        provider_environment,
        workspace,
        provider_ids,
    })
}
