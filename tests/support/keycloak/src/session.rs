// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A user signed in to the gateway with a Keycloak token.

use std::fmt;
use std::path::Path;

use serde_json::json;
use tempfile::TempDir;
use testkit::sdk::OpenShellClient;
use testkit::{Cli, Context, Error, Result, ResultExt as _};

use crate::{Keycloak, KeycloakContext, OPENSHELL_SCOPES, User};

/// A realm user signed in to the test's gateway: an SDK client and a CLI
/// that send the user's access token. Both verify the gateway with its CA
/// and present no client certificate, so the gateway authorizes the user
/// alone.
///
/// The token comes from the password grant and isn't refreshed. Keycloak's
/// access tokens outlast a test.
pub struct Session {
    user: User,
    username: String,
    subject: String,
    access_token: String,
    client: OpenShellClient,
    cli: Cli,
    // The CLI's configuration, holding the token. Removed on drop.
    _config_home: TempDir,
}

impl KeycloakContext<'_> {
    /// Sign `user` in to the test's gateway. See [`Session::login`].
    pub async fn session(&self, user: User) -> Result<Session> {
        Session::login(self, self.keycloak(), user).await
    }
}

impl Session {
    /// Log `user` in with the password grant and connect as them.
    pub async fn login(cx: &Context, keycloak: &Keycloak, user: User) -> Result<Self> {
        let (username, _) = keycloak.credentials(user)?;
        let grant = keycloak.password_grant_as(user, OPENSHELL_SCOPES).await?;
        let subject = crate::subject(&grant.access_token)?;
        let base = cx.cli_handle();
        let gateway = base.gateway();
        let client = gateway
            .connect_with_token(Some(&grant.access_token))
            .await
            .context(format!("connect as {username}"))?;
        let config_home = tempfile::tempdir().context("create a CLI config directory")?;
        write_cli_session(config_home.path(), gateway, keycloak, &grant.access_token)?;
        let cli = base.with_env("XDG_CONFIG_HOME", config_home.path());
        Ok(Self {
            user,
            username,
            subject,
            access_token: grant.access_token,
            client,
            cli,
            _config_home: config_home,
        })
    }

    pub fn user(&self) -> User {
        self.user
    }

    /// The Keycloak username, such as `user@test`.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The token's subject, which names the user in workspace memberships.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// An SDK client that sends the user's token.
    pub fn client(&self) -> &OpenShellClient {
        &self.client
    }

    /// The CLI, signed in as the user, pointed at the test's workspace.
    pub fn cli(&self) -> &Cli {
        &self.cli
    }

    /// The CLI, signed in as the user, pointed at `workspace`.
    pub fn cli_in(&self, workspace: &str) -> Cli {
        self.cli.clone().in_workspace(workspace)
    }
}

/// Write the CLI configuration `openshell gateway add --oidc-issuer` and a
/// login would: the registration, the token, and the gateway's CA, with no
/// client certificate.
fn write_cli_session(
    config_home: &Path,
    gateway: &testkit::Gateway,
    keycloak: &Keycloak,
    access_token: &str,
) -> Result {
    let name = gateway.name.as_deref().ok_or_else(|| {
        Error::msg("signing a user in to the CLI needs a registered gateway, not an endpoint")
    })?;
    let port = url::Url::parse(&gateway.endpoint)
        .ok()
        .and_then(|url| url.port_or_known_default())
        .ok_or_else(|| Error::msg(format!("no port in {}", gateway.endpoint)))?;
    let dir = config_home.join("openshell").join("gateways").join(name);
    std::fs::create_dir_all(&dir).context(format!("create {}", dir.display()))?;
    let metadata = json!({
        "name": name,
        "gateway_endpoint": gateway.endpoint,
        "is_remote": false,
        "gateway_port": port,
        "auth_mode": "oidc",
        "oidc_issuer": keycloak.issuer(),
        "oidc_client_id": keycloak.client_id(),
        "oidc_scopes": OPENSHELL_SCOPES,
    });
    write(&dir.join("metadata.json"), &metadata.to_string())?;
    let token = json!({
        "access_token": access_token,
        "issuer": keycloak.issuer(),
        "client_id": keycloak.client_id(),
    });
    write(&dir.join("oidc_token.json"), &token.to_string())?;
    if let Some(mtls) = gateway.mtls_dir() {
        let target = dir.join("mtls");
        std::fs::create_dir_all(&target).context(format!("create {}", target.display()))?;
        std::fs::copy(mtls.join("ca.crt"), target.join("ca.crt"))
            .context(format!("copy the gateway CA from {}", mtls.display()))?;
    }
    Ok(())
}

fn write(path: &Path, contents: &str) -> Result {
    std::fs::write(path, contents).context(format!("write {}", path.display()))
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("username", &self.username)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}
