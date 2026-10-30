// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider OAuth refresh against Keycloak.
//!
//! Keycloak is only the provider's token issuer here; the CLI still reaches
//! the gateway the usual way. Ported from
//! `tests/suites/features/provider-refresh/keycloak`, which tmachine's
//! `provider-refresh` testsuite runs until the required lanes switch.

use std::io::Write as _;

use keycloak::KeycloakContext;
use testkit::{CliOutput, Context, Error, ResultExt as _};

const CREDENTIAL_KEY: &str = "KEYCLOAK_ACCESS_TOKEN";

/// A provider refreshes a valid Keycloak grant. Once Keycloak revokes the
/// grant, the next refresh fails with `invalid_grant` and the provider reports
/// that the user must reauthorize.
#[testkit::test]
async fn revoked_refresh_grant_requires_user_reauthorization(cx: &mut Context) -> testkit::Result {
    let kc = KeycloakContext::new(cx).await?;
    let provider = kc.name("kc-refresh");
    let profile_id = kc.name("kc-refresh-profile");
    let grant = kc.keycloak().password_grant().await?;
    let profile = write_profile(&profile_id, kc.keycloak())?;
    let profile_path = profile.path().to_string_lossy().into_owned();

    let result = async {
        kc.cli(["profile", "import", "--file", &profile_path])
            .await?
            .success()?;
        kc.cli_with_env(
            &[(CREDENTIAL_KEY, &grant.access_token)],
            [
                "provider",
                "create",
                "--name",
                &provider,
                "--type",
                &profile_id,
                "--credential",
                CREDENTIAL_KEY,
            ],
        )
        .await?
        .success()?;
        let client_id = format!("client_id={}", kc.keycloak().client_id());
        kc.cli_with_env(
            &[("KEYCLOAK_REFRESH_TOKEN", &grant.refresh_token)],
            [
                "provider",
                "refresh",
                "configure",
                &provider,
                "--credential-key",
                CREDENTIAL_KEY,
                "--strategy",
                "oauth2-refresh-token",
                "--material",
                &client_id,
                "--secret-material-env",
                "refresh_token=KEYCLOAK_REFRESH_TOKEN",
            ],
        )
        .await?
        .success()?;

        let refresh = |verb: &'static str| {
            [
                "provider",
                "refresh",
                verb,
                provider.as_str(),
                "--credential-key",
                CREDENTIAL_KEY,
            ]
        };

        kc.cli(refresh("rotate")).await?.success()?;
        let status = kc.cli(refresh("status")).await?.success()?;
        testkit::ensure!(
            combined(&status).contains("refreshed"),
            "a valid refresh did not reach the refreshed state:\n{}",
            combined(&status)
        );

        kc.keycloak().revoke(&grant.refresh_token).await?;
        let rotate = kc.cli(refresh("rotate")).await?.failure()?;
        testkit::ensure!(
            combined(&rotate).contains("invalid_grant"),
            "a revoked refresh failed without invalid_grant:\n{}",
            combined(&rotate)
        );

        let status = combined(&kc.cli(refresh("status")).await?.success()?);
        for expected in [
            "reauthorization_required",
            "reauthorize",
            "oauth_invalid_grant",
        ] {
            testkit::ensure!(
                status.contains(expected),
                "the revoked refresh status omits {expected}:\n{}",
                status
            );
        }
        // A parked refresh is scheduled at i64::MAX; it must not render as a date.
        testkit::ensure!(
            !status.contains("292278994"),
            "the parked refresh rendered its scheduling sentinel as a date:\n{}",
            status
        );
        Ok(())
    }
    .await;

    // testkit cleans up sandboxes, not providers or profiles, so remove them
    // here whether or not the test passed. A panic or a killed test process
    // skips this; the names are unique to the run, so leftovers don't collide.
    let _ = kc.cli(["provider", "delete", &provider]).await;
    let _ = kc.cli(["profile", "delete", &profile_id]).await;
    result
}

fn combined(output: &CliOutput) -> String {
    format!("{}{}", output.stdout, output.stderr)
}

fn write_profile(
    profile_id: &str,
    keycloak: &keycloak::Keycloak,
) -> testkit::Result<tempfile::NamedTempFile> {
    let issuer_token_url = keycloak.token_endpoint();
    let profile = format!(
        r#"id: {profile_id}
display_name: Keycloak provider refresh test
category: other
credentials:
  - name: access_token
    env_vars: [{CREDENTIAL_KEY}]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_refresh_token
      token_url: {issuer_token_url}
      scopes: [openid]
      refresh_before_seconds: 60
      max_lifetime_seconds: 3600
      material:
        - name: client_id
          required: true
        - name: refresh_token
          required: true
          secret: true
endpoints:
  - host: keycloak.test.invalid
    port: 443
    protocol: rest
    access: read-only
    enforcement: enforce
binaries:
  - /usr/bin/curl
"#
    );
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| Error::from_error(&error))
        .context("create provider profile")?;
    file.write_all(profile.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|error| Error::from_error(&error))
        .context("write provider profile")?;
    Ok(file)
}
