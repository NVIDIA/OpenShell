// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::context::Context;
use crate::error::{Result, ResultExt as _};
use crate::yaml_file::YamlFile;

/// Import `profile`, a provider profile whose `id` is `name`, and create a
/// provider called `name` of that type with `credentials`, as pairs of
/// environment variable and value. Cleanup deletes the provider, then the
/// profile, after the test's sandboxes.
///
/// The CLI reads the credential values from its environment, so they aren't
/// in the reported command.
pub async fn install_provider(
    cx: &Context,
    name: &str,
    profile: &str,
    credentials: &[(&str, &str)],
) -> Result {
    crate::ensure!(
        profile
            .lines()
            .any(|line| line.trim_end() == format!("id: {name}")),
        "the profile for provider {name} must have `id: {name}`"
    );
    // Both deletes succeed for a missing resource, so register them before
    // the creates. Hooks run last registered first.
    for kind in ["profile", "provider"] {
        let cli = cx.cli_handle();
        let owned = name.to_string();
        cx.on_cleanup(format!("delete {kind} {name}"), async move || {
            cli.run([kind, "delete", &owned]).await?.success()?;
            Ok(())
        });
    }

    let file = YamlFile::new(profile)?;
    cx.cli(["profile", "import", "--file", file.path()?])
        .await?
        .success()
        .context(format!("import profile {name}"))?;
    let mut args = vec!["provider", "create", "--name", name, "--type", name];
    for (key, _) in credentials {
        args.extend(["--credential", key]);
    }
    cx.cli_with_env(credentials, args)
        .await?
        .success()
        .context(format!("create provider {name}"))?;
    Ok(())
}
