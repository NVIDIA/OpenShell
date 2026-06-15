# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for deploy/sbom/resolve_licenses.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from resolve_licenses import needs_fix


def test_empty_licenses_needs_fix() -> None:
    assert needs_fix({"licenses": []})


def test_no_licenses_key_needs_fix() -> None:
    assert needs_fix({})


def test_sha256_in_license_id_needs_fix() -> None:
    assert needs_fix({"licenses": [{"license": {"id": "sha256:abc123"}}]})


def test_sha256_in_license_name_needs_fix() -> None:
    assert needs_fix({"licenses": [{"license": {"name": "sha256:abc123"}}]})


def test_sha256_expression_needs_fix() -> None:
    assert needs_fix({"licenses": [{"expression": "sha256:abc123"}]})


def test_valid_spdx_expression_no_fix() -> None:
    assert not needs_fix({"licenses": [{"expression": "MIT OR Apache-2.0"}]})


def test_valid_license_id_no_fix() -> None:
    assert not needs_fix({"licenses": [{"license": {"id": "MIT"}}]})


def test_valid_license_name_no_fix() -> None:
    assert not needs_fix({"licenses": [{"license": {"name": "MIT"}}]})
