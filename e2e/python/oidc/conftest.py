# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""OIDC e2e test fixtures.

Overrides the parent conftest's session fixtures that assume unauthenticated
gRPC access, since the OIDC-enabled gateway requires Bearer tokens.
"""

import pytest


@pytest.fixture(scope="session")
def sandbox_client():
    """Stub — OIDC tests manage their own authenticated gRPC connections."""
    pytest.skip("OIDC tests do not use the shared sandbox_client fixture")


@pytest.fixture(scope="session", autouse=True)
def ensure_sandbox_persistence_ready():
    """No-op — OIDC tests skip the unauthenticated persistence check."""
