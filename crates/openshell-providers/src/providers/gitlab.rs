// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "gitlab",
    credential_env_vars: &["GITLAB_TOKEN", "GLAB_TOKEN", "CI_JOB_TOKEN"],
};

test_discovers_env_credential!(discovers_gitlab_env_credentials, "GLAB_TOKEN", "glab-token");
