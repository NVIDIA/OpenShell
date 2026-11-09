// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

use crate::context::Context;
use crate::error::{Error, Result, ResultExt as _};
use crate::yaml_file::YamlFile;

/// Import `profile`, a provider profile in YAML, and return its `id`, the
/// provider type it defines. Cleanup deletes the profile after the test's
/// sandboxes and the providers created after it.
pub async fn import_profile(cx: &Context, profile: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Profile {
        id: String,
    }
    let id = serde_yml::from_str::<Profile>(profile)
        .map_err(|error| Error::from_error(&error))
        .context("read the provider profile's id")?
        .id;
    // Deleting a missing profile succeeds, so register the delete before the
    // import.
    on_cleanup_delete(cx, "profile", &id);
    let file = YamlFile::new(profile)?;
    cx.cli(["profile", "import", "--file", file.path()?])
        .await?
        .success()
        .context(format!("import profile {id}"))?;
    Ok(id)
}

/// Create a provider called `name` of `provider_type` with `credentials`, as
/// pairs of environment variable and value. Cleanup deletes the provider
/// after the test's sandboxes.
///
/// The CLI reads the credential values from its environment, so they aren't
/// in the reported command.
pub async fn create_provider(
    cx: &Context,
    name: &str,
    provider_type: &str,
    credentials: &[(&str, &str)],
) -> Result {
    // Deleting a missing provider succeeds, so register the delete before the
    // create.
    on_cleanup_delete(cx, "provider", name);
    let mut args = vec![
        "provider",
        "create",
        "--name",
        name,
        "--type",
        provider_type,
    ];
    for (key, _) in credentials {
        args.extend(["--credential", key]);
    }
    cx.cli_with_env(credentials, args)
        .await?
        .success()
        .context(format!("create provider {name}"))?;
    Ok(())
}

/// Import `profile` with [`import_profile`] and create a provider called
/// `name` of its type with [`create_provider`].
pub async fn install_provider(
    cx: &Context,
    name: &str,
    profile: &str,
    credentials: &[(&str, &str)],
) -> Result {
    let provider_type = import_profile(cx, profile).await?;
    create_provider(cx, name, &provider_type, credentials).await
}

fn on_cleanup_delete(cx: &Context, kind: &'static str, name: &str) {
    let cli = cx.cli_handle();
    let owned = name.to_string();
    cx.on_cleanup(format!("delete {kind} {name}"), async move || {
        cli.run([kind, "delete", &owned]).await?.success()?;
        Ok(())
    });
}
