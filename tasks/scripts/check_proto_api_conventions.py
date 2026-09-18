# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check mechanical public protobuf API conventions."""

import re
import sys
from dataclasses import dataclass
from pathlib import Path

PUBLIC_API_FILES = (Path("proto/openshell.proto"), Path("proto/sandbox.proto"))
WORKSPACE_SELECTOR = "openshell.datamodel.v1.WorkspaceSelector"
LEGACY_REFERENCE_FIELDS = {
    "interceptor_name",
    "middleware_name",
    "profile_name",
    "provider_name",
    "rule_name",
    "sandbox_name",
    "sandbox_template_name",
    "service_name",
    "workspace_name",
    "workload_template_name",
}

MESSAGE_RE = re.compile(r"^\s*message\s+(\w+)\s*\{")
FIELD_RE = re.compile(
    r"^\s*(?:(?:optional|required|repeated)\s+)?([.\w]+)\s+(\w+)\s*=\s*\d+"
)


@dataclass(frozen=True)
class Field:
    type_name: str
    name: str
    line: int


@dataclass(frozen=True)
class Message:
    name: str
    line: int
    fields: tuple[Field, ...]


def parse_messages(path: Path) -> list[Message]:
    messages: list[Message] = []
    current_name: str | None = None
    current_line = 0
    fields: list[Field] = []
    depth = 0

    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.split("//", maxsplit=1)[0]
        if current_name is None:
            match = MESSAGE_RE.match(line)
            if match is None:
                continue
            current_name = match.group(1)
            current_line = line_number
            fields = []
            depth = line.count("{") - line.count("}")
            if depth == 0:
                messages.append(Message(current_name, current_line, ()))
                current_name = None
            continue

        if depth == 1:
            match = FIELD_RE.match(line)
            if match is not None:
                fields.append(Field(match.group(1), match.group(2), line_number))

        depth += line.count("{") - line.count("}")
        if depth == 0:
            messages.append(Message(current_name, current_line, tuple(fields)))
            current_name = None

    return messages


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    for message in parse_messages(path):
        if not message.name.endswith("Request"):
            continue

        workspace_fields = [
            field for field in message.fields if field.name == "workspace_scope"
        ]
        for field in workspace_fields:
            if field.type_name != WORKSPACE_SELECTOR:
                errors.append(
                    f"{path}:{field.line}: {message.name}.workspace_scope must use "
                    f"{WORKSPACE_SELECTOR}"
                )
            if message.fields[0] != field:
                errors.append(
                    f"{path}:{field.line}: {message.name}.workspace_scope must be "
                    "declared first"
                )

        for field in message.fields:
            if field.name in LEGACY_REFERENCE_FIELDS:
                errors.append(
                    f"{path}:{field.line}: {message.name}.{field.name} uses a "
                    "redundant entity-reference suffix; use name for the primary "
                    "resource or its role for a related resource"
                )

    return errors


def main() -> int:
    errors = [error for path in PUBLIC_API_FILES for error in check_file(path)]
    if errors:
        print("Public protobuf API convention violations:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Public protobuf API conventions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
