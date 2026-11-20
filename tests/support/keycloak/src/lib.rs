// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A Keycloak fixture for suites that need an OIDC issuer.
//!
//! The environment runs Keycloak and publishes how to reach it in
//! `OPENSHELL_TEST_KEYCLOAK_*` variables. Under `openshell-test-runner`, the
//! tmachine `ubuntu-docker-rootful-keycloak` environment does that
//! (`tests/tmachine/ansible/playbooks/keycloak.yaml`); against your own
//! deployment, set them yourself:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENSHELL_TEST_KEYCLOAK_ISSUER` | `http://127.0.0.1:8180/realms/openshell` |
//! | `OPENSHELL_TEST_KEYCLOAK_CLIENT_ID` | `openshell-cli` |
//! | `OPENSHELL_TEST_KEYCLOAK_USERNAME` | `admin@test` |
//! | `OPENSHELL_TEST_KEYCLOAK_PASSWORD` | `admin` |
//! | `OPENSHELL_TEST_KEYCLOAK_USER_USERNAME` | `user@test` |
//! | `OPENSHELL_TEST_KEYCLOAK_USER_PASSWORD` | `user` |
//! | `OPENSHELL_TEST_KEYCLOAK_USER_B_USERNAME` | `user-b@test` |
//! | `OPENSHELL_TEST_KEYCLOAK_USER_B_PASSWORD` | `user-b` |
//!
//! The issuer must be reachable from the test process. The client must allow
//! password grants. The `USER` and `USER_B` variables name plain users, and
//! are read only by tests that sign in as them ([`User`]). The tmachine
//! `<base>-oidc` environment publishes them (`playbooks/oidc.yaml`). A missing variable fails the test; it never skips it.
//! The fixture waits for the realm to answer, since Keycloak may still be
//! starting when the tests begin.
//!
//! A test builds the fixture from its testkit [`Context`]:
//!
//! ```ignore
//! #[testkit::test]
//! async fn example(cx: &mut testkit::Context) -> testkit::Result {
//!     let kc = keycloak_support::KeycloakContext::new(cx).await?;
//!     let grant = kc.keycloak().password_grant().await?;
//!     kc.cli(["status"]).await?.success()?; // Context methods still work
//!     Ok(())
//! }
//! ```
//!
//! A suite whose gateway trusts the realm signs users in to it with
//! [`KeycloakContext::session`]: a [`Session`] holds an SDK client and a CLI
//! that send the user's token. [`browser_login`] runs the CLI's own browser
//! login once, with curl as the browser. The tmachine `<base>-oidc`
//! environment (`tests/tmachine/ansible/playbooks/oidc.yaml`) runs such a
//! gateway.
//!
//! The fixture owns no Keycloak state, so it has nothing to clean up. Tests
//! that create resources in Keycloak or `OpenShell` must remove them, for
//! example with [`Context::on_cleanup`].

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use testkit::{Context, Error, Poll, Result, ResultExt as _, poll_until};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

mod browser;
mod session;
mod token;

pub use browser::{BrowserLogin, browser_login};
pub use session::Session;
pub use token::{audience_contains, claims, has_realm_role, subject};

pub const ISSUER_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_ISSUER";
pub const CLIENT_ID_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_CLIENT_ID";
pub const USERNAME_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USERNAME";
pub const PASSWORD_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_PASSWORD";
pub const USER_USERNAME_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USER_USERNAME";
pub const USER_PASSWORD_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USER_PASSWORD";
pub const USER_B_USERNAME_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USER_B_USERNAME";
pub const USER_B_PASSWORD_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USER_B_PASSWORD";
/// The scopes a login asks for so the gateway authorizes its token. The
/// `OpenShell` scopes are optional on the client, so Keycloak grants them
/// only when asked.
pub const OPENSHELL_SCOPES: &str = "openid profile email openshell:all";
/// How long Keycloak has to start answering, e.g. after the environment boots.
// The wait runs inside the test, so it must leave room for the test body
// within the runner's 2-minute per-test budget (`slow-timeout` in
// tests/runner/src/bundle.rs). Otherwise a slow Keycloak gets the test killed
// instead of failing with a readiness error. `poll_until` checks the deadline
// only between attempts, so the wait can last this plus one request
// (`CURL_MAX_TIME`) and one interval: 87 seconds, leaving 33 for the test.
pub const READY_TIMEOUT: Duration = Duration::from_secs(75);
/// How long one request to Keycloak may take, in seconds. `poll_until` checks
/// its deadline only between attempts, so a request to a Keycloak that
/// accepts connections but stalls must give up on its own.
const CURL_MAX_TIME: &str = "10";

/// How to reach the environment's Keycloak realm, and a user in it.
#[derive(Clone)]
pub struct Keycloak {
    issuer: String,
    client_id: String,
    username: String,
    password: String,
}

/// A user in the realm. [`User::Admin`] is the user the
/// `OPENSHELL_TEST_KEYCLOAK_USERNAME` variables name; the others are plain
/// users, read from their own variables only when a test logs in as them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum User {
    /// A platform admin.
    Admin,
    /// A user with no platform role beyond signing in.
    User,
    /// A second plain user, for tests across two users' workspaces.
    UserB,
}

impl User {
    fn env(self) -> (&'static str, &'static str) {
        match self {
            Self::Admin => (USERNAME_ENV, PASSWORD_ENV),
            Self::User => (USER_USERNAME_ENV, USER_PASSWORD_ENV),
            Self::UserB => (USER_B_USERNAME_ENV, USER_B_PASSWORD_ENV),
        }
    }
}

/// Tokens from one Keycloak login.
#[derive(Clone)]
pub struct Grant {
    pub access_token: String,
    pub refresh_token: String,
}

/// A testkit [`Context`] plus the environment's Keycloak. Derefs to the
/// `Context`, so its methods work unchanged.
pub struct KeycloakContext<'a> {
    cx: &'a mut Context,
    keycloak: Keycloak,
}

impl<'a> KeycloakContext<'a> {
    /// Read the Keycloak configuration from the environment and wait until
    /// the realm answers.
    pub async fn new(cx: &'a mut Context) -> Result<Self> {
        let keycloak = Keycloak::from_env()?;
        keycloak.wait_ready().await?;
        Ok(Self { cx, keycloak })
    }

    pub fn keycloak(&self) -> &Keycloak {
        &self.keycloak
    }
}

impl Deref for KeycloakContext<'_> {
    type Target = Context;

    fn deref(&self) -> &Context {
        self.cx
    }
}

impl DerefMut for KeycloakContext<'_> {
    fn deref_mut(&mut self) -> &mut Context {
        self.cx
    }
}

impl Keycloak {
    /// Read `OPENSHELL_TEST_KEYCLOAK_*`. Fails naming the first missing
    /// variable.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            issuer: required(ISSUER_ENV)?.trim_end_matches('/').to_string(),
            client_id: required(CLIENT_ID_ENV)?,
            username: required(USERNAME_ENV)?,
            password: required(PASSWORD_ENV)?,
        })
    }

    /// The realm's issuer URL, e.g. `http://127.0.0.1:8180/realms/openshell`.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Wait until the realm's discovery document is served.
    pub async fn wait_ready(&self) -> Result {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        poll_until(
            &format!("Keycloak realm at {}", self.issuer),
            READY_TIMEOUT,
            Duration::from_secs(2),
            async || {
                let output = Command::new("curl")
                    .args([
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--max-time",
                        CURL_MAX_TIME,
                        "--output",
                        "/dev/null",
                        &url,
                    ])
                    .kill_on_drop(true)
                    .output()
                    .await
                    .context("run curl")?;
                Ok(if output.status.success() {
                    Poll::Ready(())
                } else {
                    Poll::Pending(String::from_utf8_lossy(&output.stderr).trim().to_string())
                })
            },
        )
        .await
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer)
    }

    /// Log in as the configured user with the password grant.
    pub async fn password_grant(&self) -> Result<Grant> {
        self.grant(&self.username, &self.password, "openid").await
    }

    /// Log in as `user` with the password grant, asking for `scope`, such
    /// as [`OPENSHELL_SCOPES`].
    pub async fn password_grant_as(&self, user: User, scope: &str) -> Result<Grant> {
        let (username, password) = self.credentials(user)?;
        self.grant(&username, &password, scope).await
    }

    /// The username and password of `user`.
    pub fn credentials(&self, user: User) -> Result<(String, String)> {
        if user == User::Admin {
            return Ok((self.username.clone(), self.password.clone()));
        }
        let (username, password) = user.env();
        Ok((required(username)?, required(password)?))
    }

    async fn grant(&self, username: &str, password: &str, scope: &str) -> Result<Grant> {
        let client_id = format!("client_id={}", self.client_id);
        let username_field = format!("username={username}");
        let scope = format!("scope={scope}");
        let stdout = post_form(
            &self.token_endpoint(),
            &["grant_type=password", &client_id, &username_field, &scope],
            ("password", password),
        )
        .await
        .context(format!("Keycloak password grant for {username}"))?;

        let response: Value =
            serde_json::from_slice(&stdout).context("decode Keycloak grant response")?;
        let token = |name: &str| {
            response
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| Error::msg(format!("Keycloak grant response has no {name}")))
        };
        Ok(Grant {
            access_token: token("access_token")?,
            refresh_token: token("refresh_token")?,
        })
    }

    /// End the Keycloak session behind `refresh_token`, so refreshing with it
    /// fails with `invalid_grant`.
    pub async fn revoke(&self, refresh_token: &str) -> Result {
        let client_id = format!("client_id={}", self.client_id);
        post_form(
            &format!("{}/protocol/openid-connect/logout", self.issuer),
            &[&client_id],
            ("refresh_token", refresh_token),
        )
        .await
        .context("Keycloak logout")?;
        Ok(())
    }
}

fn required(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "{name} is not set; this suite needs a Keycloak realm (see the keycloak-support crate docs)"
            ))
        })
}

/// POST a URL-encoded form with curl and return the response body. `secret`
/// goes through stdin, so it isn't in curl's arguments or in errors.
async fn post_form(url: &str, fields: &[&str], secret: (&str, &str)) -> Result<Vec<u8>> {
    let mut command = Command::new("curl");
    command.args([
        "--fail-with-body",
        "--silent",
        "--show-error",
        "--max-time",
        CURL_MAX_TIME,
        "--request",
        "POST",
        url,
    ]);
    for field in fields {
        command.args(["--data-urlencode", field]);
    }
    command.args(["--data-urlencode", &format!("{}@-", secret.0)]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("run curl")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(secret.1.as_bytes())
        .await
        .context("write request body")?;
    drop(stdin);
    let output = child.wait_with_output().await.context("wait for curl")?;
    testkit::ensure!(
        output.status.success(),
        "POST {url} failed ({}): {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

impl fmt::Debug for Keycloak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keycloak")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant").finish_non_exhaustive()
    }
}
