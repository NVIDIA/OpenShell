// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "tars",
    credential_env_vars: &["TARS_API_KEY", "AGENTROUTER_API_KEY"],
};

test_discovers_env_credential!(
    discovers_tars_env_credentials,
    "TARS_API_KEY",
    "sk-tars-test-123"
);
