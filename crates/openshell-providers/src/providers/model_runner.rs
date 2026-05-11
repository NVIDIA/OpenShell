// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{DiscoveredProvider, ProviderError, ProviderPlugin};

pub struct ModelRunnerProvider;

impl ProviderPlugin for ModelRunnerProvider {
    fn id(&self) -> &'static str {
        "model-runner"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        Ok(Some(DiscoveredProvider::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::ModelRunnerProvider;
    use crate::ProviderPlugin;

    #[test]
    fn model_runner_provider_id_is_correct() {
        assert_eq!(ModelRunnerProvider.id(), "model-runner");
    }

    #[test]
    fn model_runner_discover_returns_default_provider() {
        let result = ModelRunnerProvider
            .discover_existing()
            .expect("discovery should succeed");
        assert!(result.is_some());
    }
}
