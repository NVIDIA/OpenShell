# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validation helpers for the public authored policy contract."""

from __future__ import annotations

import protovalidate

from ._proto import policy_pb2

PolicyDocument = policy_pb2.PolicyDocument


def validate_policy_document(document: PolicyDocument) -> PolicyDocument:
    """Validate a policy against the portable rules declared in policy.proto."""
    protovalidate.validate(document)
    return document
