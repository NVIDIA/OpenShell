// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "deepinfra",
    credential_env_vars: &["DEEPINFRA_API_KEY"],
};

test_discovers_env_credential!(
    discovers_deepinfra_env_credentials,
    "DEEPINFRA_API_KEY",
    "di-test123"
);
