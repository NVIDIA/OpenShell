// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ProviderDiscoverySpec;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "claude-code",
    credential_env_vars: &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
};

test_discovers_env_credential!(
    discovers_claude_env_credentials,
    "ANTHROPIC_API_KEY",
    "test-key"
);
