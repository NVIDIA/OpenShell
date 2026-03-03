# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Basic tests for the navigator package."""

import navigator


def test_version() -> None:
    """Test that version is defined."""
    assert navigator.__version__
