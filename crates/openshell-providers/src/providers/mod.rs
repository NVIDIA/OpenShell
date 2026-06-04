// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Generate a standard discovery smoke-test for a provider whose only test is
/// checking that an env-var credential is picked up by `discover_with_spec`.
///
/// # Usage
/// ```ignore
/// test_discovers_env_credential!(discovers_openai_env_credentials, "OPENAI_API_KEY", "sk-test");
/// ```
macro_rules! test_discovers_env_credential {
    ($test_name:ident, $env_var:expr, $env_value:expr) => {
        #[cfg(test)]
        mod tests {
            use super::SPEC;
            use crate::discover_with_spec;
            use crate::test_helpers::MockDiscoveryContext;

            #[test]
            fn $test_name() {
                let ctx = MockDiscoveryContext::new().with_env($env_var, $env_value);
                let discovered = discover_with_spec(&SPEC, &ctx)
                    .expect("discovery")
                    .expect("provider");
                assert_eq!(
                    discovered.credentials.get($env_var),
                    Some(&$env_value.to_string())
                );
            }
        }
    };
}
pub mod anthropic;
pub mod claude;
pub mod codex;
pub mod copilot;
pub mod generic;
pub mod github;
pub mod gitlab;
pub mod nvidia;
pub mod openai;
pub mod opencode;
pub mod outlook;
