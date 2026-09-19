# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import protovalidate
import pytest

from openshell.policy import PolicyDocument, validate_policy_document


def test_policy_document_validation_runs_portable_rules() -> None:
    assert validate_policy_document(PolicyDocument(version=1)).version == 1


def test_policy_document_validation_reports_portable_rule_ids() -> None:
    documents: list[tuple[str, PolicyDocument, str]] = []

    documents.append(("version", PolicyDocument(), "uint32.const"))

    missing_ports = PolicyDocument(version=1)
    missing_ports.network_policies["api"].endpoints.add(host="api.example.com")
    documents.append(("missing ports", missing_ports, "repeated.min_items"))

    duplicate_ports = PolicyDocument(version=1)
    duplicate_ports.network_policies["api"].endpoints.add(
        host="api.example.com", ports=[443, 443]
    )
    documents.append(("duplicate ports", duplicate_ports, "repeated.unique"))

    port_range = PolicyDocument(version=1)
    port_range.network_policies["api"].endpoints.add(
        host="api.example.com", ports=[65536]
    )
    documents.append(("port range", port_range, "uint32.gte_lte"))

    binary_path = PolicyDocument(version=1)
    binary_path.network_policies["api"].binaries.add(path="")
    documents.append(("binary path", binary_path, "string.min_len"))

    matcher_choice = PolicyDocument(version=1)
    endpoint = matcher_choice.network_policies["api"].endpoints.add(
        host="api.example.com", ports=[443]
    )
    endpoint.rules.add().allow.query["owner"].SetInParent()
    documents.append(("matcher choice", matcher_choice, "required"))

    for name, document, rule_id in documents:
        with pytest.raises(protovalidate.ValidationError) as error:
            validate_policy_document(document)

        assert rule_id in {
            violation.proto.rule_id for violation in error.value.violations
        }, name
