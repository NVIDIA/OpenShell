// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The CLI's browser (PKCE) login, with curl in place of the browser.
//!
//! The CLI opens the authorization URL with `xdg-open`. A stand-in earlier
//! on `PATH` records the URL instead, and curl signs in on Keycloak's login
//! form, following the redirect to the CLI's loopback callback.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;
use testkit::{Cli, CliOutput, Context, Error, Poll, Result, ResultExt as _, poll_until};
use tokio::process::Command;
use url::Url;

use crate::{Keycloak, User};

const URL_FILE_ENV: &str = "OPENSHELL_TEST_BROWSER_URL_FILE";
/// How long the CLI has to discover the issuer and open the browser.
const URL_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the CLI has to exchange the code and save the session after the
/// callback.
const FINISH_TIMEOUT: Duration = Duration::from_secs(30);
const CURL_MAX_TIME: &str = "10";

/// A finished `openshell gateway add --oidc-issuer` browser login.
pub struct BrowserLogin {
    /// The URL the CLI opened in the browser.
    pub authorization_url: Url,
    /// The CLI's output from `gateway add`.
    pub output: CliOutput,
    /// The page the CLI's callback served after the login.
    pub callback_page: String,
    cli: Cli,
    gateway_name: String,
    config_home: TempDir,
}

/// Register the test's gateway under its own name in a fresh CLI
/// configuration with `gateway add --oidc-issuer`, and sign in as `user` in
/// the browser it opens, asking for `scopes`. Fails if the login doesn't
/// reach the CLI's callback; the test checks the rest.
pub async fn browser_login(
    cx: &Context,
    keycloak: &Keycloak,
    user: User,
    scopes: &str,
) -> Result<BrowserLogin> {
    let (username, password) = keycloak.credentials(user)?;
    let base = cx.cli_handle();
    let gateway = base.gateway().clone();
    let gateway_name = gateway.name.clone().ok_or_else(|| {
        Error::msg("the browser login registers a named gateway; testkit has only an endpoint")
    })?;

    let config_home = tempfile::tempdir().context("create a CLI config directory")?;
    let bin = config_home.path().join("bin");
    let url_file = config_home.path().join("browser-url");
    install_xdg_open_recorder(&bin)?;
    let cli = base
        .with_env("XDG_CONFIG_HOME", config_home.path())
        .with_env("HOME", config_home.path())
        .without_env("OPENSHELL_NO_BROWSER")
        .without_env("OPENSHELL_OIDC_CLIENT_SECRET");
    let login = cli
        .clone()
        .with_env("PATH", prepend_path(&bin)?)
        .with_env(URL_FILE_ENV, &url_file)
        .spawn([
            "gateway",
            "add",
            &gateway.endpoint,
            "--name",
            &gateway_name,
            "--local",
            "--oidc-issuer",
            keycloak.issuer(),
            "--oidc-client-id",
            keycloak.client_id(),
            "--oidc-scopes",
            scopes,
        ])?;

    let authorization_url = wait_for_url(&url_file).await?;
    let cookies = config_home.path().join("keycloak-cookies");
    let login_page = curl(&["--cookie-jar"], &cookies, authorization_url.as_str(), &[])
        .await
        .context("load the Keycloak login page")?;
    let action = login_form_action(&login_page)?;
    let callback_page = curl(
        &["--location", "--cookie-jar"],
        &cookies,
        &action,
        &[
            &format!("username={username}"),
            &format!("password={password}"),
            "credentialId=",
        ],
    )
    .await
    .context("sign in on the Keycloak login page")?;
    let output = login.output(FINISH_TIMEOUT).await?;
    testkit::ensure!(
        callback_page.contains("Authentication successful"),
        "the CLI's callback did not report success:\n{callback_page}\n{}{}",
        output.stdout,
        output.stderr
    );
    Ok(BrowserLogin {
        authorization_url,
        output,
        callback_page,
        cli,
        gateway_name,
        config_home,
    })
}

impl BrowserLogin {
    /// The CLI's directory for the registered gateway, holding
    /// `metadata.json` and `oidc_token.json`.
    pub fn gateway_dir(&self) -> PathBuf {
        self.config_home
            .path()
            .join("openshell")
            .join("gateways")
            .join(&self.gateway_name)
    }

    /// The CLI signed in by this login. It trusts the gateway's CA, which an
    /// OIDC registration doesn't save, so a test can make calls with it.
    pub fn cli(&self, cx: &Context) -> Result<Cli> {
        if let Some(mtls) = cx.cli_handle().gateway().mtls_dir() {
            let target = self.gateway_dir().join("mtls");
            std::fs::create_dir_all(&target).context(format!("create {}", target.display()))?;
            std::fs::copy(mtls.join("ca.crt"), target.join("ca.crt"))
                .context(format!("copy the gateway CA from {}", mtls.display()))?;
        }
        Ok(self.cli.clone())
    }
}

fn install_xdg_open_recorder(bin: &Path) -> Result {
    std::fs::create_dir_all(bin).context(format!("create {}", bin.display()))?;
    let script = bin.join("xdg-open");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$1\" > \"${URL_FILE_ENV}\"\n"),
    )
    .context("write the xdg-open stand-in")?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .context("make the xdg-open stand-in executable")
}

fn prepend_path(bin: &Path) -> Result<std::ffi::OsString> {
    let current = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::iter::once(bin.to_path_buf()).chain(std::env::split_paths(&current)))
        .map_err(|error| Error::msg(format!("build PATH: {error}")))
}

async fn wait_for_url(path: &Path) -> Result<Url> {
    let url = poll_until(
        "the CLI to open the authorization URL",
        URL_TIMEOUT,
        Duration::from_millis(100),
        async || {
            Ok(match tokio::fs::read_to_string(path).await {
                Ok(contents) if !contents.trim().is_empty() => {
                    Poll::Ready(contents.trim().to_string())
                }
                _ => Poll::Pending(format!("nothing in {}", path.display())),
            })
        },
    )
    .await?;
    Url::parse(&url)
        .map_err(|error| Error::msg(format!("parse the authorization URL {url}: {error}")))
}

/// Request `url` with curl, keeping cookies in `jar`, and POST `form` if it
/// isn't empty. Returns the body.
async fn curl(options: &[&str], jar: &Path, url: &str, form: &[&str]) -> Result<String> {
    let mut command = Command::new("curl");
    command
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            CURL_MAX_TIME,
        ])
        .args(options)
        .arg(jar)
        .arg("--cookie")
        .arg(jar);
    for field in form {
        command.args(["--data-urlencode", field]);
    }
    let output = command
        .arg(url)
        .kill_on_drop(true)
        .output()
        .await
        .context("run curl")?;
    testkit::ensure!(
        output.status.success(),
        "curl failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The URL Keycloak's login form posts to.
fn login_form_action(html: &str) -> Result<String> {
    let missing = || Error::msg(format!("no Keycloak login form in the page:\n{html}"));
    let id = html.find("id=\"kc-form-login\"").ok_or_else(missing)?;
    let start = html[..id].rfind("<form").ok_or_else(missing)?;
    let end = id + html[id..].find('>').ok_or_else(missing)?;
    let tag = &html[start..end];
    let action = tag
        .split_once("action=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(action, _)| action)
        .ok_or_else(missing)?;
    Ok(action.replace("&amp;", "&").replace("&#38;", "&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_login_form_action() {
        let html = r#"<form class="x" id="kc-form-login" onsubmit="" action="http://kc/login?a=1&amp;b=2&#38;c=3" method="post">"#;
        assert_eq!(
            login_form_action(html).unwrap(),
            "http://kc/login?a=1&b=2&c=3"
        );
        assert!(login_form_action("<form id=\"other\">").is_err());
    }
}
