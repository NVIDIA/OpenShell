# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import random
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "perf_docker", Path(__file__).with_name("perf-docker.py")
)
perf_docker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf_docker)

ORIGINAL = ["cpu", "getpid", "file", "spawn", "tcp-connect", "tcp-stream"]


def result(case, count, **extra):
    return dict(
        {
            "case": case,
            "iterations": count,
            "elapsed_ns": 10,
            "uid": 1000,
            "gid": 1000,
            "cwd": "/sandbox",
        },
        **extra,
    )


def test_original_cases_keep_their_definition_and_counts():
    assert list(perf_docker.COUNTS) == ORIGINAL
    assert perf_docker.COUNTS == {
        "cpu": 100_000_000,
        "getpid": 1_000_000,
        "file": 50_000,
        "spawn": 200,
        "tcp-connect": 1_000,
        "tcp-stream": 20_000,
    }
    assert not set(perf_docker.COUNTS) & set(perf_docker.ATTRIBUTION_COUNTS)


def test_attribution_cases_never_reorder_the_original_six():
    for trial in range(32):
        legacy = list(ORIGINAL)
        random.Random(trial).shuffle(legacy)
        assert perf_docker.case_order(trial, attribution=False) == legacy
        with_attribution = perf_docker.case_order(trial, attribution=True)
        assert with_attribution[: len(legacy)] == legacy
        assert sorted(with_attribution[len(legacy) :]) == sorted(
            perf_docker.ATTRIBUTION_COUNTS
        )


def test_workload_output_must_describe_the_requested_case():
    assert perf_docker.validate_result(result("file", 5), "file", 5)
    assert not perf_docker.validate_result(result("file", 5), "file-open", 5)
    assert not perf_docker.validate_result(result("file", 4), "file", 5)
    assert not perf_docker.validate_result(result("file", 5, uid=0), "file", 5)
    assert not perf_docker.validate_result(result("file", 5, elapsed_ns=0), "file", 5)
    assert not perf_docker.validate_result({"case": "file"}, "file", 5)


def test_latency_case_requires_ordered_percentiles():
    latency = {"p50_ns": 1_000, "p99_ns": 2_000, "max_ns": 9_000}
    assert perf_docker.validate_result(
        result("file-latency", 5, **latency), "file-latency", 5
    )
    assert not perf_docker.validate_result(
        result("file-latency", 5), "file-latency", 5
    )
    assert not perf_docker.validate_result(
        result("file-latency", 5, **dict(latency, p99_ns=500)), "file-latency", 5
    )


def test_report_includes_attribution_and_latency_rows():
    samples = []
    for trial in range(2):
        for mode, scale in (("docker", 1), ("openshell", 3)):
            for case in [*perf_docker.COUNTS, *perf_docker.ATTRIBUTION_COUNTS]:
                extra = (
                    {"p50_ns": 100 * scale, "p99_ns": 200 * scale, "max_ns": 900 * scale}
                    if case == "file-latency"
                    else {}
                )
                samples.append(
                    dict(
                        result(case, 1, **extra),
                        trial=trial,
                        mode=mode,
                        elapsed_ns=1_000_000 * scale,
                    )
                )
    report = perf_docker.report(
        {"started_utc": "now", "commit": "abc", "complete": True, "samples": samples}
    )
    assert "| file | 1.000 (1.000-1.000) | 3.000 (3.000-3.000) | +200.0% |" in report
    assert "| file-open |" in report
    assert "| file-t16 |" in report
    assert "| docker | 100 | 200 | 900 |" in report
    assert "| openshell | 300 | 600 | 2700 |" in report
