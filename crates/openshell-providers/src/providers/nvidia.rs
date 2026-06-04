// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "nvidia",
    credential_env_vars: &["NVIDIA_API_KEY"],
};

test_discovers_env_credential!(
    discovers_nvidia_env_credentials,
    "NVIDIA_API_KEY",
    "nvapi-123"
);
