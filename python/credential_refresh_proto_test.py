# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated refresh clients preserve additive strategy-name wire presence."""

import pytest
from google.protobuf import json_format
from google.protobuf.message import Message

from openshell._proto import openshell_pb2 as gateway

REFRESH_SCHEMAS = [
    (gateway.ProviderCredentialRefresh, 106, 1),
    (gateway.ProviderCredentialRefreshStatus, 114, 4),
    (gateway.ConfigureProviderRefreshRequest, 107, 3),
]
BUILTIN_STRATEGIES = [
    (
        gateway.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN,
        "oauth2_refresh_token",
    ),
    (
        gateway.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS,
        "oauth2_client_credentials",
    ),
    (
        gateway.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT,
        "google_service_account_jwt",
    ),
    (
        gateway.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE,
        "aws_sts_assume_role",
    ),
]


@pytest.mark.parametrize("schema,name_tag,enum_tag", REFRESH_SCHEMAS)
def test_strategy_name_field_is_additive_and_optional(
    schema: type[Message], name_tag: int, enum_tag: int
) -> None:
    field = schema.DESCRIPTOR.fields_by_name["strategy_name"]
    assert field.number == name_tag
    assert field.json_name == "strategyName"
    assert field.has_presence
    assert schema.DESCRIPTOR.fields_by_name["strategy"].number == enum_tag


@pytest.mark.parametrize("schema,name_tag,enum_tag", REFRESH_SCHEMAS)
@pytest.mark.parametrize("strategy,canonical_name", BUILTIN_STRATEGIES)
def test_strategy_selectors_preserve_wire_and_json_presence(
    schema: type[Message],
    name_tag: int,
    enum_tag: int,
    strategy: int,
    canonical_name: str,
) -> None:
    # These are wire tests, not server validation: explicitly empty names must
    # remain distinguishable from omission so the server can reject them.
    for selectors in [
        {},
        {"strategy_name": ""},
        {"strategy": strategy},
        {"strategy_name": canonical_name},
        {"strategy": strategy, "strategy_name": canonical_name},
    ]:
        original = schema(**selectors)
        has_name = "strategy_name" in selectors
        assert original.HasField("strategy_name") is has_name
        wire = original.SerializeToString()
        # All strategy enum values fit one varint byte; field tags are fixed.
        if "strategy" in selectors:
            assert wire.startswith(bytes([enum_tag << 3, strategy]))
        if has_name:
            tag = (name_tag << 3) | 2
            name = selectors["strategy_name"]
            assert isinstance(name, str)
            name_bytes = name.encode()
            assert wire.endswith(
                bytes([(tag & 0x7F) | 0x80, tag >> 7, len(name_bytes)]) + name_bytes
            )
        decoded = schema.FromString(wire)
        assert decoded == original
        assert decoded.HasField("strategy_name") is has_name
        payload = json_format.MessageToDict(original)
        assert ("strategyName" in payload) is has_name
        if has_name:
            assert payload["strategyName"] == selectors["strategy_name"]
        for json_value in [
            payload,
            json_format.MessageToDict(original, preserving_proto_field_name=True),
        ]:
            restored = json_format.ParseDict(json_value, schema())
            assert restored == original
            assert restored.HasField("strategy_name") is has_name
        assert (
            json_format.Parse(json_format.MessageToJson(original), schema()) == original
        )
