# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Basic tests for the openshell package."""

import openshell


def test_version() -> None:
    """Test that version is defined."""
    assert openshell.__version__


def test_sandbox_template_exports() -> None:
    assert openshell.SandboxWorkloadConfig is not None
    assert openshell.SandboxTemplate is not None
    assert openshell.SandboxTemplateSpec is not None
    assert openshell.SandboxTemplateClient is not None
