// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspaces a test creates, and their members.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use openshell_sdk::raw::proto;
use openshell_sdk::{DeleteOptions, OpenShellClient};

use serde::Deserialize;

use crate::cleanup::Cleanup;
use crate::cli::Cli;
use crate::context::{Context, track_sandbox};
use crate::error::{Error, Result, ResultExt as _};
use crate::yaml_file::YamlFile;

/// The longest workspace name the gateway accepts.
const MAX_WORKSPACE_NAME_LEN: usize = 19;

/// How long cleanup waits for a workspace's resources to go before giving
/// up on deleting it. Under [`crate::CLEANUP_TIMEOUT`], so the failure
/// names the workspace.
const DELETE_RETRY_TIMEOUT: Duration = Duration::from_secs(90);
const DELETE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

impl Context {
    /// Create a workspace named [`Context::name`]`(suffix)`, as the gateway
    /// client testkit connects with. The suffix is at most five characters,
    /// to fit the gateway's limit on workspace names. Cleanup deletes the
    /// workspace after the test's sandboxes, waiting for resources still in
    /// it to go.
    pub async fn workspace(&self, suffix: &str) -> Result<Workspace> {
        let name = self.name(suffix);
        crate::ensure!(
            name.len() <= MAX_WORKSPACE_NAME_LEN,
            "workspace name {name} exceeds {MAX_WORKSPACE_NAME_LEN} characters; use a shorter suffix than {suffix:?}"
        );
        let client = self.gateway_client().clone();
        // Deleting a missing workspace succeeds, so register the delete
        // before the create.
        let cleanup_client = client.clone();
        let owned = name.clone();
        self.on_cleanup(format!("delete workspace {name}"), move || {
            delete_workspace(cleanup_client, owned)
        });
        client
            .create_workspace(&name, HashMap::new())
            .await
            .context(format!("create workspace {name}"))?;
        Ok(Workspace {
            cli: self.cli_handle().in_workspace(&name),
            name,
            client,
            cleanup: self.cleanup_list().clone(),
        })
    }
}

/// A workspace from [`Context::workspace`].
#[derive(Clone)]
pub struct Workspace {
    name: String,
    client: OpenShellClient,
    cli: Cli,
    cleanup: Cleanup,
}

impl Workspace {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Delete sandbox `name` in the workspace when the test ends, before the
    /// workspace. Call it before the sandbox is created, by whoever creates
    /// it, so cleanup deletes it even if the test fails first.
    pub fn track_sandbox(&self, name: &str) {
        track_sandbox(&self.cleanup, &self.client.workspace(&self.name), name);
    }

    /// Delete provider `name` in the workspace when the test ends, before the
    /// workspace. Call it before the provider is created.
    pub fn track_provider(&self, name: &str) {
        let client = self.client.clone();
        let workspace = self.name.clone();
        let owned = name.to_string();
        self.cleanup.push(
            format!("delete provider {name} in workspace {workspace}"),
            async move || {
                client
                    .raw_grpc_fresh()
                    .await?
                    .delete_provider(proto::DeleteProviderRequest {
                        workspace_scope: Some(proto::workspace_selector(&workspace)),
                        name: owned,
                        allow_missing: true,
                        request_id: String::new(),
                    })
                    .await?;
                Ok(())
            },
        );
    }

    /// Import `profile`, a provider profile in YAML, into the workspace and
    /// return its `id`. Cleanup deletes it after the workspace's providers.
    pub async fn import_profile(&self, profile: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Profile {
            id: String,
        }
        let id = serde_yml::from_str::<Profile>(profile)
            .context("read the provider profile's id")?
            .id;
        // Deleting a missing profile succeeds, so register the delete before
        // the import.
        let cli = self.cli.clone();
        let owned = id.clone();
        self.cleanup.push(
            format!("delete profile {id} in workspace {}", self.name),
            async move || {
                cli.run(["profile", "delete", &owned]).await?.success()?;
                Ok(())
            },
        );
        let file = YamlFile::new(profile)?;
        self.cli
            .run(["profile", "import", "--file", file.path()?])
            .await?
            .success()
            .context(format!("import profile {id} into workspace {}", self.name))?;
        Ok(id)
    }

    /// Make `subject`, an OIDC subject claim, a member with `role`.
    pub async fn add_member(&self, subject: &str, role: proto::WorkspaceRole) -> Result {
        self.client
            .raw_grpc_fresh()
            .await?
            .add_workspace_member(proto::AddWorkspaceMemberRequest {
                workspace_scope: Some(proto::workspace_selector(&self.name)),
                principal_subject: subject.to_string(),
                role: role.into(),
                request_id: String::new(),
            })
            .await
            .context(format!(
                "add {subject} to workspace {} as {}",
                self.name,
                role.as_str_name()
            ))?;
        Ok(())
    }

    /// Remove `subject` from the workspace's members.
    pub async fn remove_member(&self, subject: &str) -> Result {
        self.client
            .raw_grpc_fresh()
            .await?
            .remove_workspace_member(proto::RemoveWorkspaceMemberRequest {
                workspace_scope: Some(proto::workspace_selector(&self.name)),
                principal_subject: subject.to_string(),
                allow_missing: false,
                request_id: String::new(),
            })
            .await
            .context(format!("remove {subject} from workspace {}", self.name))?;
        Ok(())
    }
}

/// Delete `name`, retrying while resources the gateway is still deleting
/// block it.
async fn delete_workspace(client: OpenShellClient, name: String) -> Result {
    let started = Instant::now();
    loop {
        let error = match client
            .delete_workspace(
                &name,
                DeleteOptions {
                    allow_missing: true,
                },
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => Error::from(error),
        };
        if !still_has_resources(&error) || started.elapsed() >= DELETE_RETRY_TIMEOUT {
            return Err(error).context(format!("delete workspace {name}"));
        }
        tokio::time::sleep(DELETE_RETRY_INTERVAL).await;
    }
}

fn still_has_resources(error: &Error) -> bool {
    error.grpc_code() == Some(tonic::Code::FailedPrecondition)
        && error.to_string().contains("still contains resources")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_only_a_workspace_with_resources() {
        let busy = Error::from(tonic::Status::failed_precondition(
            "workspace 'w' still contains resources: sandbox",
        ));
        let other = Error::from(tonic::Status::failed_precondition(
            "workspace is terminating",
        ));
        let denied = Error::from(tonic::Status::permission_denied("still contains resources"));
        assert!(still_has_resources(&busy));
        assert!(!still_has_resources(&other));
        assert!(!still_has_resources(&denied));
    }
}
