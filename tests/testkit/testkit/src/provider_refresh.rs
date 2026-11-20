// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cli::{Cli, CliOutput};
use crate::context::Context;
use crate::error::Result;

impl Context {
    /// The `provider refresh` commands for the credential `key` of
    /// `provider`.
    pub fn provider_refresh(&self, provider: &str, key: &str) -> ProviderRefresh {
        ProviderRefresh {
            cli: self.cli_handle(),
            provider: provider.to_string(),
            key: key.to_string(),
        }
    }
}

/// The `provider refresh` commands for one provider credential, from
/// [`Context::provider_refresh`]. Each returns the CLI output whatever the
/// exit code; check it with [`CliOutput::success`] or
/// [`CliOutput::failure`].
#[derive(Clone, Debug)]
pub struct ProviderRefresh {
    cli: Cli,
    provider: String,
    key: String,
}

impl ProviderRefresh {
    /// `provider refresh configure` with `strategy`, such as
    /// `oauth2-client-credentials`, the plain `material` pairs and the
    /// `secret_material` pairs. The CLI reads each secret from its
    /// environment, so the values aren't in the reported command.
    pub async fn configure(
        &self,
        strategy: &str,
        material: &[(&str, &str)],
        secret_material: &[(&str, &str)],
    ) -> Result<CliOutput> {
        let mut args = self.args("configure");
        args.extend(["--strategy".to_string(), strategy.to_string()]);
        for (name, value) in material {
            args.extend(["--material".to_string(), format!("{name}={value}")]);
        }
        let env_vars: Vec<String> = secret_material
            .iter()
            .map(|(name, _)| format!("TESTKIT_REFRESH_{}", name.to_ascii_uppercase()))
            .collect();
        for ((name, _), env_var) in secret_material.iter().zip(&env_vars) {
            args.extend([
                "--secret-material-env".to_string(),
                format!("{name}={env_var}"),
            ]);
        }
        let env: Vec<(&str, &str)> = env_vars
            .iter()
            .zip(secret_material)
            .map(|(env_var, (_, value))| (env_var.as_str(), *value))
            .collect();
        self.cli.run_with_env(None, &env, args).await
    }

    /// `provider refresh rotate`, which refreshes the credential now.
    pub async fn rotate(&self) -> Result<CliOutput> {
        self.cli.run(self.args("rotate")).await
    }

    /// `provider refresh status`.
    pub async fn status(&self) -> Result<CliOutput> {
        self.cli.run(self.args("status")).await
    }

    fn args(&self, verb: &str) -> Vec<String> {
        [
            "provider",
            "refresh",
            verb,
            &self.provider,
            "--credential-key",
            &self.key,
        ]
        .map(str::to_string)
        .to_vec()
    }
}
