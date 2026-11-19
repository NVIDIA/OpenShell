#!/usr/bin/python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Apply an environment's gateway overrides to a gateway.toml.

usage: merge-gateway-toml.py BASE OVERRIDES [--default DEFAULT]

OVERRIDES holds whole tables, such as `[openshell.gateway]` or
`[openshell.drivers.podman]`. Each key in it replaces the same key in BASE's
table, or is added to the table, and a table BASE lacks is appended. Everything
else in BASE stays, including its comments, so a package's own configuration is
never replaced. Running it again with the same overrides changes nothing.

If BASE does not exist it is created first: from DEFAULT when that file exists
(the rpm's packaged default), else as a minimal `version = 2` file. The merged
text is parsed as TOML before it is written, and the script fails, leaving BASE
as it was, if it is not valid.

The overrides must be valid TOML, and the script fails if any of their values is
missing from the merged result, so a statement it cannot rewrite is an error
rather than a silent no-op.

Limits: a key's value in BASE is replaced as written lines, up to the next key,
header, comment or blank line. A key can't be removed.
"""

import argparse
import os
import re
import sys
import tomllib

HEADER = re.compile(r"^\s*\[([^\[\]]+)\]\s*(#.*)?$")
ARRAY_HEADER = re.compile(r"^\s*\[\[[^\[\]]+\]\]\s*(#.*)?$")
KEY = re.compile(r"^\s*([A-Za-z0-9_-]+|\"[^\"]+\"|'[^']+')\s*=")
MINIMAL = "[openshell]\nversion = 2\n"


def table_name(line):
    return re.sub(r"\s+", "", HEADER.match(line).group(1))


def is_boundary(line):
    """A table or array-of-tables header ends the current table."""
    return bool(HEADER.match(line) or ARRAY_HEADER.match(line))


def key_name(raw):
    return raw[1:-1] if raw[0] in "\"'" else raw


def is_statement_start(line):
    return bool(is_boundary(line) or KEY.match(line))


def is_break(line):
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def statements(lines):
    """The (key, lines) pairs of a table body, in order."""
    found = []
    for line in lines:
        key = KEY.match(line)
        if key:
            found.append((key_name(key.group(1)), [line]))
        elif found and not is_break(line):
            found[-1][1].append(line)
    return found


def override_tables(text):
    if any(line.lstrip().startswith("[[") for line in text.splitlines()):
        sys.exit("array-of-tables headers are not supported in the overrides")
    tables, current = {}, None
    for line in text.splitlines():
        if HEADER.match(line):
            current = table_name(line)
            tables.setdefault(current, [])
        elif current is not None:
            tables[current].append(line)
        elif not is_break(line):
            sys.exit(f"override key outside a table: {line!r}")
    return {name: statements(body) for name, body in tables.items()}


def apply(lines, table, new):
    start = next(
        (i for i, l in enumerate(lines) if HEADER.match(l) and table_name(l) == table),
        None,
    )
    if start is None:
        return lines + ["", f"[{table}]", *(l for _, stmt in new for l in stmt)]
    for key, stmt in new:
        end = next(
            (i for i in range(start + 1, len(lines)) if is_boundary(lines[i])),
            len(lines),
        )
        existing = next(
            (
                i
                for i in range(start + 1, end)
                if (m := KEY.match(lines[i])) and key_name(m.group(1)) == key
            ),
            None,
        )
        if existing is None:
            lines[start + 1 : start + 1] = stmt
            continue
        stop = existing + 1
        while stop < end and not is_statement_start(lines[stop]) and not is_break(lines[stop]):
            stop += 1
        lines[existing:stop] = stmt
    return lines


def contains(merged, expected):
    """Whether every table and value in EXPECTED is present in MERGED."""
    if isinstance(expected, dict):
        return isinstance(merged, dict) and all(
            k in merged and contains(merged[k], v) for k, v in expected.items()
        )
    return merged == expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("overrides")
    parser.add_argument("--default")
    args = parser.parse_args()

    created = not os.path.exists(args.base)
    if not created:
        text = open(args.base).read()
    elif args.default and os.path.exists(args.default):
        text = open(args.default).read()
    else:
        text = MINIMAL
    lines = text.splitlines()
    override_text = open(args.overrides).read()
    try:
        wanted = tomllib.loads(override_text)
    except tomllib.TOMLDecodeError as error:
        sys.exit(f"{args.overrides} is not valid TOML: {error}")
    for table, new in override_tables(override_text).items():
        lines = apply(lines, table, new)
    merged = "\n".join(lines) + "\n"
    try:
        result = tomllib.loads(merged)
    except tomllib.TOMLDecodeError as error:
        sys.exit(f"merged {args.base} is not valid TOML: {error}")
    # The rewriter works on lines, so confirm every override really landed
    # rather than trusting it to have handled each statement.
    if not contains(result, wanted):
        sys.exit(f"the overrides in {args.overrides} were not all applied to {args.base}")
    with open(args.base, "w") as out:
        out.write(merged)
    if created:
        os.chmod(args.base, 0o644)


main()
