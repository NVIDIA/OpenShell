// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

use crate::context::Context;
use crate::error::{Error, Result, ResultExt as _};
use crate::yaml_file::YamlFile;

impl Context {
    /// Import `profile`, a provider profile in YAML, and return its `id`, the
    /// provider type it defines. Cleanup deletes the profile after the test's
    /// sandboxes and the providers created after it.
    pub async fn import_profile(&self, profile: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Profile {
            id: String,
        }
        let id = serde_yml::from_str::<Profile>(profile)
            .map_err(|error| Error::from_error(&error))
            .context("read the provider profile's id")?
            .id;
        // Deleting a missing profile succeeds, so register the delete before
        // the import.
        self.on_cleanup_delete("profile", &id);
        let file = YamlFile::new(profile)?;
        self.cli(["profile", "import", "--file", file.path()?])
            .await?
            .success()
            .context(format!("import profile {id}"))?;
        Ok(id)
    }

    /// Create a provider called `name` of `provider_type` with `credentials`,
    /// as pairs of environment variable and value. Cleanup deletes the
    /// provider after the test's sandboxes.
    ///
    /// The CLI reads the credential values from its environment, so they
    /// aren't in the reported command.
    pub async fn create_provider(
        &self,
        name: &str,
        provider_type: &str,
        credentials: &[(&str, &str)],
    ) -> Result {
        // Deleting a missing provider succeeds, so register the delete before
        // the create.
        self.on_cleanup_delete("provider", name);
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
        self.cli_with_env(credentials, args)
            .await?
            .success()
            .context(format!("create provider {name}"))?;
        Ok(())
    }

    /// Import `profile` with [`Context::import_profile`] and create a provider
    /// called `name` of its type with [`Context::create_provider`].
    pub async fn install_provider(
        &self,
        name: &str,
        profile: &str,
        credentials: &[(&str, &str)],
    ) -> Result {
        let provider_type = self.import_profile(profile).await?;
        self.create_provider(name, &provider_type, credentials)
            .await
    }

    fn on_cleanup_delete(&self, kind: &'static str, name: &str) {
        let cli = self.cli_handle();
        let owned = name.to_string();
        self.on_cleanup(format!("delete {kind} {name}"), async move || {
            cli.run([kind, "delete", &owned]).await?.success()?;
            Ok(())
        });
    }
}
