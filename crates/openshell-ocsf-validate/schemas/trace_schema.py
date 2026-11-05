# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prepare Trace-profile exports without relaxing unrelated OCSF constraints.

The server exports Trace on HTTP/API Activity only. Other supported classes use
an explicitly marked OpenShell extension composed from the official HTTP export.
Run through update.sh, which fetches both inputs for the requested OCSF version.
"""

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

CLASS_UIDS = {
    "api_activity": 6003,
    "application_lifecycle": 6002,
    "authentication": 3002,
    "base_event": 0,
    "detection_finding": 2004,
    "device_config_state_change": 5019,
    "http_activity": 4002,
    "network_activity": 4001,
    "process_activity": 1007,
    "ssh_activity": 4007,
}
NATIVE_TRACE_CLASSES = {"api_activity", "http_activity"}
TRACE_DEFINITIONS = {"trace", "span", "service", "key_value_object"}
PROFILES = {
    "ai_operation",
    "container",
    "host",
    "network_proxy",
    "security_control",
    "trace",
}
DRAFT = "http://json-schema.org/draft-07/schema#"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def references(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            else:
                yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def check_class(schema, name):
    require(isinstance(schema, dict), "export must be a JSON object")
    require(schema.get("$schema") == DRAFT, "unexpected JSON Schema draft")
    require(schema.get("$id", "").endswith("/classes/" + name), "class ID URL mismatch")
    require(schema.get("type") == "object", "event schema must describe an object")
    require(
        schema.get("additionalProperties") is False,
        "event schema must reject undefined fields",
    )
    require(
        schema.get("properties", {}).get("class_uid", {}).get("const")
        == CLASS_UIDS[name],
        "class_uid mismatch",
    )


def trace_closure(schema):
    prop = schema.get("properties", {}).get("trace")
    require(
        isinstance(prop, dict) and prop.get("$ref") == "#/$defs/trace",
        "missing official Trace property",
    )
    definitions = schema.get("$defs", {})
    found = set()
    pending = list(references(prop))
    while pending:
        ref = pending.pop()
        require(
            isinstance(ref, str) and ref.startswith("#/$defs/"),
            "non-local Trace reference",
        )
        name = ref[len("#/$defs/") :]
        require(name in TRACE_DEFINITIONS, "unexpected Trace definition: " + name)
        if name in found:
            continue
        require(name in definitions, "unresolved Trace reference: " + name)
        found.add(name)
        pending.extend(references(definitions[name]))
    require(found == TRACE_DEFINITIONS, "incomplete official Trace definition closure")
    trace = definitions["trace"]
    require(
        trace.get("type") == "object" and trace.get("additionalProperties") is False,
        "malformed Trace object",
    )
    require(
        trace.get("properties", {}).get("uid", {}).get("type") == "string",
        "Trace UID must be a string",
    )
    require(trace.get("required") == ["uid"], "unexpected required Trace attributes")
    return prop, {name: definitions[name] for name in sorted(found)}


def prepare_schema(schema, donor, class_name, version, profiles):
    require(version == "1.8.0", "Trace composition is reviewed for OCSF 1.8.0 only")
    require(class_name in CLASS_UIDS, "unsupported event class")
    require(profiles == sorted(set(profiles)), "profiles must be unique and sorted")
    require(
        "trace" in profiles and set(profiles) <= PROFILES,
        "unsupported Trace profile combination",
    )
    require(
        "ai_operation" not in profiles or class_name == "api_activity",
        "AI profile requires API Activity",
    )
    require(
        "network_proxy" not in profiles
        or class_name in {"http_activity", "network_activity"},
        "network proxy profile requires HTTP/Network Activity",
    )
    check_class(schema, class_name)
    check_class(donor, "http_activity")
    trace_property, definitions = trace_closure(donor)
    if class_name in NATIVE_TRACE_CLASSES:
        native_property, native_definitions = trace_closure(schema)
        require(
            native_property == trace_property and native_definitions == definitions,
            "native Trace export differs from the HTTP donor",
        )
        return copy.deepcopy(schema)
    require(
        "trace" not in schema["properties"],
        "class now exports Trace natively; review extension applicability",
    )
    result = copy.deepcopy(schema)
    result["properties"]["trace"] = copy.deepcopy(trace_property)
    result_definitions = result.setdefault("$defs", {})
    for name, definition in definitions.items():
        require(
            name not in result_definitions or result_definitions[name] == definition,
            "conflicting shared definition: " + name,
        )
        result_definitions[name] = copy.deepcopy(definition)
    result["$comment"] = (
        "OpenShell extension: OCSF 1.8.0 does not declare the Trace profile for "
        + class_name
        + ". The optional trace property and its definition closure are copied unchanged from "
        "https://schema.ocsf.io/schema/1.8.0/classes/http_activity?profiles=container,host,network_proxy,security_control,trace. "
        "All other class constraints are preserved. Regenerate with schemas/update.sh."
    )
    return result


def main():
    require(
        len(sys.argv) == 4,
        "usage: trace_schema.py TARGET CLASS_EXPORT HTTP_TRACE_EXPORT",
    )
    target, class_export, donor_export = map(Path, sys.argv[1:])
    require(
        target.parent.name.startswith("v"), "target must name an OCSF version directory"
    )
    require("@" in target.stem, "target must name its profiles")
    class_name, profile_names = target.stem.split("@", 1)
    profiles = profile_names.split("+")
    untraced = target.with_name(
        class_name + "@" + "+".join(p for p in profiles if p != "trace") + ".json"
    )
    require(
        untraced.is_file(),
        "vendor the corresponding untraced profile combination first",
    )
    if os.environ.get("OCSF_TRACE_SCHEMA_EXPORT"):
        expected = os.environ.get("OCSF_TRACE_SCHEMA_SHA256", "")
        require(
            len(expected) == 64 and all(c in "0123456789abcdef" for c in expected),
            "a cached donor requires OCSF_TRACE_SCHEMA_SHA256 from its source receipt",
        )
        require(
            hashlib.sha256(donor_export.read_bytes()).hexdigest() == expected,
            "cached donor SHA-256 mismatch",
        )
    schema = json.loads(class_export.read_text())
    donor = json.loads(donor_export.read_text())
    result = prepare_schema(schema, donor, class_name, target.parent.name[1:], profiles)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError) as error:
        raise SystemExit("Trace schema generation failed: " + str(error)) from error
