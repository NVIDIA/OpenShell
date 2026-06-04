// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "github",
    credential_env_vars: &["GITHUB_TOKEN", "GH_TOKEN"],
};

test_discovers_env_credential!(discovers_github_env_credentials, "GH_TOKEN", "gh-token");
