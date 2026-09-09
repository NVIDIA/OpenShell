# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Summarize recorded live evidence without changing test expectations."""

import json
import math
import statistics
from collections import defaultdict

from run import OUT


def percentile(values, p):
    values = sorted(values)
    return values[max(0, math.ceil(p * len(values)) - 1)]


def main():
    if (OUT / "tunnel-raw.json").exists():
        grouped = defaultdict(list)
        for record in json.loads((OUT / "tunnel-raw.json").read_text()):
            grouped[(record["name"], record["size"])].extend(record["samples"])
        tunnel_summary = []
        for (name, size), samples in grouped.items():
            times = [x["time_total"] * 1000 for x in samples]
            baseline = statistics.median(
                x["time_total"] * 1000 for x in grouped[("baseline", size)]
            )
            median = statistics.median(times)
            tunnel_summary.append(
                {
                    "name": name,
                    "size": size,
                    "n": len(times),
                    "median_ms": median,
                    "p95_ms": percentile(times, 0.95),
                    "overhead_ms": median - baseline,
                    "connections": sum(x["num_connects"] for x in samples),
                }
            )
        (OUT / "tunnel-summary.json").write_text(json.dumps(tunnel_summary, indent=2))
    results = json.loads((OUT / "matrix-results.json").read_text())
    summary = {
        "cases": len(results),
        "passed": sum(r["passed"] for r in results),
        "failed": [
            {"name": r["case"]["name"], "checks": r["checks"]}
            for r in results
            if not r["passed"]
        ],
    }
    chains = []
    for r in results:
        case = r["case"]
        if case["name"].startswith(("pair-", "triple-")):
            preflights = [e for e in r["events"] if e["kind"] == "preflight"]
            checks = {
                "stage_order": [e["service"] for e in preflights]
                == [f"fixture-{i + 1}" for i in range(len(case["stages"]))]
            }
            for i, stage in enumerate(case["stages"]):
                events = [e for e in r["events"] if e["service"] == f"fixture-{i + 1}"]
                units = [e for e in events if e["kind"] == "body"]
                if stage["mode"] == 1:
                    checks[f"stage-{i + 1}-no-body"] = not units
                else:
                    checks[f"stage-{i + 1}-sequence"] = [
                        u["seq"] for u in units
                    ] == list(range(1, len(units) + 1))
                    checks[f"stage-{i + 1}-final"] = (
                        sum(u["final"] for u in units) == 1 and units[-1]["final"]
                    )
                    checks[f"stage-{i + 1}-trailers"] = (
                        sum(e["kind"] == "trailers" for e in events) == 1
                    )
                    if stage["mode"] == 2:
                        checks[f"stage-{i + 1}-whole"] = len(units) == 1
            chains.append(
                {"name": case["name"], "checks": checks, "passed": all(checks.values())}
            )
    summary["chain_event_checks"] = chains
    (OUT / "functional-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if not (OUT / "benchmark-raw.json").exists():
        return
    records = json.loads((OUT / "benchmark-raw.json").read_text())
    groups = defaultdict(list)
    rounds = defaultdict(list)
    for r in records:
        key = (r["name"], r["size"], r["fresh"])
        groups[key].extend(r["samples"])
        rounds[key].append(
            statistics.median(x["time_total"] for x in r["samples"]) * 1000
        )
    bench = []
    for (name, size, fresh), samples in groups.items():
        times = [x["time_total"] * 1000 for x in samples]
        baseline = [x["time_total"] * 1000 for x in groups[("baseline", size, fresh)]]
        median = statistics.median(times)
        bench.append(
            {
                "name": name,
                "size": size,
                "fresh": fresh,
                "n": len(times),
                "median_ms": median,
                "p95_ms": percentile(times, 0.95),
                "overhead_ms": median - statistics.median(baseline),
                "ttfb_median_ms": statistics.median(
                    x["time_starttransfer"] for x in samples
                )
                * 1000,
                "connections": sum(x["num_connects"] for x in samples),
                "round_median_ms": rounds[(name, size, fresh)],
            }
        )
    (OUT / "benchmark-summary.json").write_text(json.dumps(bench, indent=2))
    print("\nBenchmark summary")
    for r in sorted(bench, key=lambda x: (x["fresh"], x["size"], x["median_ms"])):
        print(
            f"{r['name']:24} size={r['size']:7} fresh={r['fresh']} n={r['n']:3} median={r['median_ms']:.3f} p95={r['p95_ms']:.3f} delta={r['overhead_ms']:+.3f} connections={r['connections']}"
        )


if __name__ == "__main__":
    main()
