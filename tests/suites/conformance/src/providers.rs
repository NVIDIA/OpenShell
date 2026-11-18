// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Providers attached to a sandbox: files a provider profile serves, and
//! providers that `sandbox create --provider` creates from local credentials.

use testkit::policy::{self, Access, Endpoint as _};
use testkit::{Context, Credential, Profile, ResultExt as _, YamlFile};

/// The example profile that serves `client.toml` from the provider's config.
const FILES_PROFILE: &str =
    include_str!("../../../../examples/provider-managed-files/acme-config.yaml");
const AUTO_CREATE_ENV: &str = "E2E_AUTO_PROVIDER_KEY";
const AUTO_CREATE_SECRET: &str = "sk-e2e-auto-provider-test-key";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// A provider profile's file is readable at the path its environment variable
/// names, with mode 600 and no write access. Updating the provider's config
/// updates the file, and detaching the provider removes it.
#[testkit::test]
async fn provider_file_open_update_and_detach(cx: &mut Context) -> testkit::Result {
    let provider = cx.name("pf");
    let profile = FILES_PROFILE.replace("id: acme-config", &format!("id: {provider}"));
    cx.install_provider(&provider, &profile, &[])
        .config("endpoint", "https://api.acme.example")
        .config("project", "production")
        .await?;

    let sandbox = cx
        .sandbox("pf")
        .spec(|spec| spec.providers = vec![provider.clone()])
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    let path = format!("/run/openshell/providers/{provider}/client.toml");
    sandbox
        .exec(["printenv", "ACME_CONFIG_FILE"])
        .await?
        .expect_stdout(&format!("{path}\n"))
        .context("the provider file's environment variable")?;
    expect_project(&sandbox, &path, "production").await?;
    sandbox
        .exec([
            "sh",
            "-c",
            &format!(
                "set -eu; exec 3<{path}; test \"$(stat -Lc %a /proc/self/fd/3)\" = 600; \
                 test \"$(stat -Lc %F /proc/self/fd/3)\" = 'regular file'; \
                 if (printf x >&3) 2>/dev/null; then exit 1; fi"
            ),
        ])
        .await?
        .success()
        .context("the provider file is a read-only regular file with mode 600")?;

    cx.cli([
        "provider",
        "update",
        &provider,
        "--config",
        "project=staging",
        "--wait",
        "--timeout",
        "90",
    ])
    .await?
    .success()?;
    expect_project(&sandbox, &path, "staging").await?;

    cx.cli([
        "sandbox",
        "provider",
        "detach",
        sandbox.name(),
        &provider,
        "--wait",
        "--timeout",
        "90",
    ])
    .await?
    .success()?;
    let detached = sandbox.exec(["cat", &path]).await?.failure()?;
    testkit::ensure!(
        detached.stderr.contains("No such file or directory"),
        "the detached provider's file is still there: {}",
        detached.stderr
    );
    Ok(())
}

/// `sandbox create --provider <profile id> --auto-providers` creates a
/// provider named after a profile from the credential in the CLI's
/// environment. The sandbox gets a placeholder for the credential, not the
/// secret.
#[testkit::test]
async fn auto_created_provider_credential_available_in_sandbox(
    cx: &mut Context,
) -> testkit::Result {
    let provider = cx
        .import_profile(&auto_create_profile(&cx.name("auto")).to_yaml()?)
        .await?;
    // The CLI names the provider it creates after the profile.
    let cli = cx.cli_handle();
    let name = provider.clone();
    cx.on_cleanup(format!("delete provider {provider}"), async move || {
        cli.run(["provider", "delete", &name]).await?.success()?;
        Ok(())
    });

    // The test only reads the environment. A policy without network rules
    // keeps the default policy's rules from conflicting with the provider's.
    let policy = YamlFile::new(&policy::to_yaml(&policy::base())?)?;
    let sandbox_name = cx.name("ac");
    let image = testkit::python_image();
    cx.track(&sandbox_name);
    let create = cx
        .cli_with_env(
            &[(AUTO_CREATE_ENV, AUTO_CREATE_SECRET)],
            [
                "sandbox",
                "create",
                "--name",
                &sandbox_name,
                "--no-tty",
                "--detach",
                "--from",
                &image,
                "--policy",
                policy.path()?,
                "--provider",
                &provider,
                "--auto-providers",
                "--",
                "sh",
                "-c",
                "exec sleep infinity",
            ],
        )
        .await?
        .success()?;
    testkit::ensure!(
        create
            .report_text()
            .contains(&format!("Created provider {provider}")),
        "sandbox create did not report creating provider {provider}:\n{}{}",
        create.stdout,
        create.stderr
    );

    let sandbox = cx.adopt(&sandbox_name).await?;
    sandbox.wait_ready().await?;
    let output = sandbox
        .exec(["printenv", AUTO_CREATE_ENV])
        .await?
        .success()?;
    let value = output.stdout.trim();
    testkit::ensure!(
        !value.contains(AUTO_CREATE_SECRET),
        "the sandbox has the raw credential in {AUTO_CREATE_ENV}"
    );
    testkit::ensure!(
        is_placeholder_for(value, AUTO_CREATE_ENV),
        "expected a placeholder for {AUTO_CREATE_ENV} in the sandbox; got {value:?}"
    );
    Ok(())
}

async fn expect_project(sandbox: &testkit::Sandbox, path: &str, project: &str) -> testkit::Result {
    let content = sandbox.exec(["cat", path]).await?.success()?.stdout;
    testkit::ensure!(
        content.contains(&format!("project = \"{project}\"")),
        "expected project {project} in the provider file:\n{content}"
    );
    Ok(())
}

/// A profile `id` whose credential the CLI discovers in [`AUTO_CREATE_ENV`].
/// Its endpoint makes the gateway inject the credential without a policy
/// binding; nothing connects to it.
fn auto_create_profile(id: &str) -> Profile {
    Profile::new(id)
        .display_name("E2E Auto-created Provider")
        .credential(
            Credential::new("api_key")
                .env_var(AUTO_CREATE_ENV)
                .required()
                .auth_style("header")
                .header_name("x-api-key"),
        )
        .discover(["api_key"])
        .endpoint("api.auto-provider.example", 443, |ep| {
            ep.rest(Access::ReadWrite).enforce();
        })
        .binaries(["/usr/bin/curl"])
}

/// Whether `value` is the placeholder for the credential in `key`, in the
/// unversioned or the revisioned form.
fn is_placeholder_for(value: &str, key: &str) -> bool {
    value == format!("{PLACEHOLDER_PREFIX}{key}")
        || (value.starts_with(&format!("{PLACEHOLDER_PREFIX}v"))
            && value.ends_with(&format!("_{key}")))
}
