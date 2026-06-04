// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "copilot",
    credential_env_vars: &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"],
};

test_discovers_env_credential!(
    discovers_copilot_env_credentials,
    "COPILOT_GITHUB_TOKEN",
    "ghp-copilot-token"
);
