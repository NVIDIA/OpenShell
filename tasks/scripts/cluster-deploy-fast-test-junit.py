#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert cluster-deploy-fast TSV summary into JUnit XML."
    )
    parser.add_argument("--input", required=True, help="Path to summary.tsv")
    parser.add_argument("--output", required=True, help="Path to junit.xml")
    parser.add_argument(
        "--suite-name",
        default="cluster-deploy-fast-nightly",
        help="JUnit testsuite name",
    )
    return parser.parse_args()


def as_seconds(value: str) -> str:
    if not value or value == "n/a":
        return "0"
    try:
        return str(float(value))
    except ValueError:
        return "0"


def build_xml(rows: list[dict[str, str]], suite_name: str) -> ET.ElementTree:
    total = len(rows)
    failures = sum(1 for row in rows if row["pass"] == "FAIL")
    skipped = sum(1 for row in rows if row["pass"] == "INFO")
    suite = ET.Element(
        "testsuite",
        name=suite_name,
        tests=str(total),
        failures=str(failures),
        skipped=str(skipped),
    )

    for row in rows:
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"cluster_deploy_fast.{row['mode']}",
            name=row["scenario"],
            time=as_seconds(row["total_seconds"]),
        )

        if row["pass"] == "FAIL":
            failure = ET.SubElement(
                case,
                "failure",
                message=row["notes"] or "scenario failed",
            )
            failure.text = (
                f"Expected: {row['expected']}\n"
                f"Observed: {row['observed']}\n"
                f"Notes: {row['notes']}"
            )
        elif row["pass"] == "INFO":
            skipped = ET.SubElement(
                case,
                "skipped",
                message=row["notes"] or "informational baseline",
            )
            skipped.text = f"Observed: {row['observed']}"

        properties = ET.SubElement(case, "properties")
        for key in (
            "expected",
            "observed",
            "build_seconds",
            "cached_lines",
            "notes",
        ):
            ET.SubElement(properties, "property", name=key, value=row[key])

    return ET.ElementTree(suite)


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))

    if not rows:
        print(f"no rows found in {input_path}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tree = build_xml(rows, args.suite_name)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
