// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider OAuth refresh against Keycloak.
//!
//! Keycloak is only the provider's token issuer here; the CLI still reaches
//! the gateway the usual way.

use keycloak_support::KeycloakContext;
use testkit::policy::{Access, Endpoint as _};
use testkit::sdk::raw::proto;
use testkit::{CliOutput, Context, Credential, Profile};

fn main() -> std::process::ExitCode {
    testkit::main()
}

const CREDENTIAL_KEY: &str = "KEYCLOAK_ACCESS_TOKEN";

/// A provider refreshes a valid Keycloak grant. Once Keycloak revokes the
/// grant, the next refresh fails with `invalid_grant` and the provider reports
/// that the user must reauthorize.
#[testkit::test]
async fn revoked_refresh_grant_requires_user_reauthorization(cx: &mut Context) -> testkit::Result {
    let kc = KeycloakContext::new(cx).await?;
    let provider = kc.name("kc-refresh");
    let grant = kc.keycloak().password_grant().await?;
    let profile = refresh_profile(&kc.name("kc-refresh-profile"), kc.keycloak()).to_yaml()?;
    kc.install_provider(
        &provider,
        &profile,
        &[(CREDENTIAL_KEY, &grant.access_token)],
    )
    .await?;
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

fn combined(output: &CliOutput) -> String {
    format!("{}{}", output.stdout, output.stderr)
}

/// A profile whose `access_token` the gateway refreshes from `keycloak`
/// with the OAuth refresh-token grant.
fn refresh_profile(id: &str, keycloak: &keycloak_support::Keycloak) -> Profile {
    let material = |name: &str, secret: bool| proto::ProviderCredentialRefreshMaterial {
        name: name.to_string(),
        required: true,
        secret,
        ..proto::ProviderCredentialRefreshMaterial::default()
    };
    let seconds = |seconds| Some(prost_types::Duration { seconds, nanos: 0 });
    Profile::new(id)
        .display_name("Keycloak provider refresh test")
        .credential(
            Credential::new("access_token")
                .env_var(CREDENTIAL_KEY)
                .required()
                .auth_style("bearer")
                .header_name("authorization")
                .refresh(proto::ProviderCredentialRefresh {
                    strategy: proto::ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                    token_url: keycloak.token_endpoint(),
                    scopes: vec!["openid".to_string()],
                    refresh_before: seconds(60),
                    max_lifetime: seconds(3600),
                    material: vec![
                        material("client_id", false),
                        material("refresh_token", true),
                    ],
                    ..proto::ProviderCredentialRefresh::default()
                }),
        )
        .endpoint("keycloak.test.invalid", 443, |ep| {
            ep.rest(Access::ReadOnly).enforce();
        })
        .binaries(["/usr/bin/curl"])
}
