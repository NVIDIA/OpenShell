# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Randomized repeated curl transfers inside the sandbox. No CLI time included."""

import json
import random
import statistics

from run import CLI, NAME, OUT, command, set_policy

CONFIGS = {
    "baseline": [],
    "headers-1": [1],
    "whole-1": [2],
    "stream-1": [3],
    "headers-2": [1, 1],
    "whole-2": [2, 2],
    "stream-2": [3, 3],
    "stream-whole": [3, 2],
    "headers-whole-stream": [1, 2, 3],
}

CLIENT = """import json,subprocess
args=["curl","-sS","--max-time","10","-w","%{json}\\n"]
if FRESH: args += ["--header","Connection: close"]
if TUNNEL: args += ["--proxytunnel"]
for _ in range(COUNT): args += ["-o","/tmp/pr3074-bench-body","--url",URL]
r=subprocess.run(args,capture_output=True,text=True,timeout=120)
rows=[json.loads(x) for x in r.stdout.splitlines() if x]
assert r.returncode==0,(r.returncode,r.stderr)
assert len(rows)==COUNT,len(rows)
assert all(x["http_code"]==200 and x["size_download"]==SIZE for x in rows),rows
print(json.dumps(rows))
"""


def batch(path, size, count=40, fresh=False, tunnel=False):
    code = (
        f"URL={('http://host.openshell.internal:18081' + path)!r}\nSIZE={size}\nCOUNT={count}\nFRESH={fresh!r}\nTUNNEL={tunnel!r}\n"
        + CLIENT
    )
    return json.loads(
        command(
            [
                *CLI,
                "sandbox",
                "exec",
                "--name",
                NAME,
                "--no-tty",
                "--",
                "python3",
                "-c",
                code,
            ]
        )
    )


def main():
    rng = random.Random(3074)
    records = []
    for round in range(3):
        configs = list(CONFIGS.items())
        rng.shuffle(configs)
        for name, modes in configs:
            set_policy([{"mode": m, "quiet": True} for m in modes], "bench-" + name)
            for size in [19, 65536, 262144]:
                path = "/fixed" if size == 19 else f"/fixed?size={size}"
                rows = batch(path, size, 40)
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
                    f"round={round} {name:24} bytes={size:7} median_ms={statistics.median(x['time_total'] for x in samples) * 1000:.3f}",
                    flush=True,
                )
                (OUT / "benchmark-raw.json").write_text(json.dumps(records, indent=2))
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
            f"fresh {name} median_ms={statistics.median(x['time_total'] for x in rows[5:]) * 1000:.3f}",
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


if __name__ == "__main__":
    main()
