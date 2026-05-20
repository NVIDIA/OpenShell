// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "gitlab",
    credential_env_vars: &["GITLAB_TOKEN", "GLAB_TOKEN", "CI_JOB_TOKEN"],
};

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_gitlab_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("GLAB_TOKEN", "glab-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("GLAB_TOKEN"),
            Some(&"glab-token".to_string())
        );
    }
}
