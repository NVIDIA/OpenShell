# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import statistics

from bench import CONFIGS, batch
from run import OUT, set_policy

records = json.loads((OUT / "benchmark-raw.json").read_text())
for name in ["baseline", "headers-1", "whole-1", "stream-1", "stream-2"]:
    set_policy([{"mode": m, "quiet": True} for m in CONFIGS[name]], "bench-" + name)
    rows = batch("/fixed", 19, 40, fresh=True)
    records.append(
        {
            "round": 0,
            "name": name,
            "size": 19,
            "fresh": True,
            "warmup": rows[:5],
            "samples": rows[5:],
        }
    )
    print(
        f"explicit close {name} median_ms={statistics.median(x['time_total'] for x in rows[5:]) * 1000:.3f}",
        flush=True,
    )
(OUT / "benchmark-raw.json").write_text(json.dumps(records, indent=2))
latency = []
for name in ["baseline", "headers-1", "whole-1", "stream-1", "stream-whole"]:
    set_policy([{"mode": m, "quiet": True} for m in CONFIGS[name]], "bench-" + name)
    rows = batch("/slow", 19, 15)
    latency.append({"name": name, "samples": rows[3:]})
    print(
        f"slow {name} TTFB_ms={statistics.median(x['time_starttransfer'] for x in rows[3:]) * 1000:.3f} total_ms={statistics.median(x['time_total'] for x in rows[3:]) * 1000:.3f}",
        flush=True,
    )
(OUT / "streaming-latency.json").write_text(json.dumps(latency, indent=2))
