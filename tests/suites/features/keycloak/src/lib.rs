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
//!
//! The issuer must be reachable from the test process. The client must allow
//! password grants. A missing variable fails the test; it never skips it.
//! The fixture waits for the realm to answer, since Keycloak may still be
//! starting when the tests begin.
//!
//! A test builds the fixture from its testkit [`Context`]:
//!
//! ```ignore
//! #[testkit::test]
//! async fn example(cx: &mut testkit::Context) -> testkit::Result {
//!     let kc = keycloak::KeycloakContext::new(cx).await?;
//!     let grant = kc.keycloak().password_grant().await?;
//!     kc.cli(["status"]).await?.success()?; // Context methods still work
//!     Ok(())
//! }
//! ```
//!
//! The fixture owns no Keycloak state, so it has nothing to clean up. Tests
//! that create resources in Keycloak or `OpenShell` must remove them.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use testkit::{Context, Error, Poll, Result, ResultExt as _, poll_until};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

pub const ISSUER_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_ISSUER";
pub const CLIENT_ID_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_CLIENT_ID";
pub const USERNAME_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_USERNAME";
pub const PASSWORD_ENV: &str = "OPENSHELL_TEST_KEYCLOAK_PASSWORD";
/// How long Keycloak has to start answering, e.g. after the environment boots.
pub const READY_TIMEOUT: Duration = Duration::from_mins(3);

/// How to reach the environment's Keycloak realm, and a user in it.
#[derive(Clone)]
pub struct Keycloak {
    issuer: String,
    client_id: String,
    username: String,
    password: String,
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
                        "--output",
                        "/dev/null",
                        &url,
                    ])
                    .output()
                    .await
                    .map_err(|error| Error::from_error(&error))
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
        let client_id = format!("client_id={}", self.client_id);
        let username = format!("username={}", self.username);
        let stdout = post_form(
            &self.token_endpoint(),
            &["grant_type=password", &client_id, &username, "scope=openid"],
            ("password", &self.password),
        )
        .await
        .context("Keycloak password grant")?;

        let response: Value = serde_json::from_slice(&stdout)
            .map_err(|error| Error::from_error(&error))
            .context("decode Keycloak grant response")?;
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
                "{name} is not set; this suite needs a Keycloak realm (see the keycloak crate docs)"
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
        .map_err(|error| Error::from_error(&error))
        .context("run curl")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(secret.1.as_bytes())
        .await
        .map_err(|error| Error::from_error(&error))
        .context("write request body")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .map_err(|error| Error::from_error(&error))
        .context("wait for curl")?;
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
