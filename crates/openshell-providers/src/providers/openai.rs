// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "openai",
    credential_env_vars: &["OPENAI_API_KEY"],
};

test_discovers_env_credential!(
    discovers_openai_env_credentials,
    "OPENAI_API_KEY",
    "sk-openai-test"
);
