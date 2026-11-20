// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use serde::Deserialize;

use crate::context::Context;
use crate::error::{Result, ResultExt as _};
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
    /// as pairs of environment variable and value, when awaited. Cleanup
    /// deletes the provider after the test's sandboxes.
    ///
    /// The CLI reads the credential values from its environment, so they
    /// aren't in the reported command. [`ProviderBuilder`] sets other
    /// `provider create` options before the await.
    pub fn create_provider<'a>(
        &'a self,
        name: &'a str,
        provider_type: &'a str,
        credentials: &'a [(&'a str, &'a str)],
    ) -> ProviderBuilder<'a> {
        ProviderBuilder::new(self, name, ProviderType::Named(provider_type), credentials)
    }

    /// Import `profile` with [`Context::import_profile`] and create a provider
    /// called `name` of its type with [`Context::create_provider`], when
    /// awaited.
    pub fn install_provider<'a>(
        &'a self,
        name: &'a str,
        profile: &'a str,
        credentials: &'a [(&'a str, &'a str)],
    ) -> ProviderBuilder<'a> {
        ProviderBuilder::new(self, name, ProviderType::Profile(profile), credentials)
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

/// Where a [`ProviderBuilder`] gets its provider type.
enum ProviderType<'a> {
    /// A profile already on the gateway.
    Named(&'a str),
    /// A profile, in YAML, to import first.
    Profile(&'a str),
}

/// A provider to create, from [`Context::create_provider`] or
/// [`Context::install_provider`]. Awaiting it creates the provider.
///
/// ```ignore
/// cx.create_provider(&name, &provider_type, &[])
///     .config("project", "production")
///     .await?;
/// ```
#[must_use = "a ProviderBuilder does nothing until awaited"]
pub struct ProviderBuilder<'a> {
    cx: &'a Context,
    name: &'a str,
    provider_type: ProviderType<'a>,
    credentials: &'a [(&'a str, &'a str)],
    config: Vec<String>,
}

impl<'a> ProviderBuilder<'a> {
    fn new(
        cx: &'a Context,
        name: &'a str,
        provider_type: ProviderType<'a>,
        credentials: &'a [(&'a str, &'a str)],
    ) -> Self {
        Self {
            cx,
            name,
            provider_type,
            credentials,
            config: Vec::new(),
        }
    }

    /// Set the provider config `key` to `value` (`--config key=value`).
    pub fn config(mut self, key: &str, value: &str) -> Self {
        self.config.push(format!("{key}={value}"));
        self
    }

    async fn create(self) -> Result {
        let provider_type = match self.provider_type {
            ProviderType::Named(provider_type) => provider_type.to_string(),
            ProviderType::Profile(profile) => self.cx.import_profile(profile).await?,
        };
        // Deleting a missing provider succeeds, so register the delete before
        // the create.
        self.cx.on_cleanup_delete("provider", self.name);
        let mut args = vec![
            "provider",
            "create",
            "--name",
            self.name,
            "--type",
            &provider_type,
        ];
        for (key, _) in self.credentials {
            args.extend(["--credential", key]);
        }
        for setting in &self.config {
            args.extend(["--config", setting]);
        }
        self.cx
            .cli_with_env(self.credentials, args)
            .await?
            .success()
            .context(format!("create provider {}", self.name))?;
        Ok(())
    }
}

impl<'a> IntoFuture for ProviderBuilder<'a> {
    type Output = Result;
    type IntoFuture = Pin<Box<dyn Future<Output = Result> + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.create())
    }
}
