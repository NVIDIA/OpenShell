# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Repeat the benchmark with CONNECT tunnels to test HTTP connection reuse."""

import json
import random
import statistics

from bench import CONFIGS, batch
from run import OUT, set_policy

rng = random.Random(3074)
records = []
for round in range(3):
    configs = list(CONFIGS.items())
    rng.shuffle(configs)
    for name, modes in configs:
        set_policy([{"mode": m, "quiet": True} for m in modes], "bench-" + name)
        for size in [19, 65536, 262144]:
            path = "/fixed" if size == 19 else f"/fixed?size={size}"
            rows = batch(path, size, 40, tunnel=True)
            samples = rows[5:]
            records.append(
                {
                    "round": round,
                    "name": name,
                    "size": size,
                    "fresh": False,
                    "warmup": rows[:5],
                    "samples": samples,
                }
            )
            print(
                f"round={round} {name:24} bytes={size:7} median_ms={statistics.median(x['time_total'] for x in samples) * 1000:.3f} connects={sum(x['num_connects'] for x in samples)}",
                flush=True,
            )
            (OUT / "tunnel-raw.json").write_text(json.dumps(records, indent=2))
