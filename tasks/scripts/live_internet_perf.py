#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compare live-Internet traffic on the host with the same traffic in a sandbox.

Creates one sandbox on the active gateway with a policy that allows the
benchmark's destinations, then alternates direct and sandbox rounds of
`live_internet_perf_round.py` so drift in the network affects both sides
alike. Each round prints one `LIVE_INTERNET_PERF` line with the round's JSON.
The sandbox is deleted on exit.

This is a manual benchmark: it needs the live Internet, and CI doesn't run it.

    mise run perf:live-internet -- --rounds 4 --from <image>
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROUND = Path(__file__).with_name("live_internet_perf_round.py")

POLICY = """version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

network_policies:
  live_internet_performance:
    name: live_internet_performance
    endpoints:
      - { host: example.com, port: 443, protocol: tcp }
      - { host: github.com, port: 443, protocol: tcp }
      - { host: raw.githubusercontent.com, port: 443, protocol: tcp }
      - { host: pypi.org, port: 443, protocol: tcp }
      - { host: files.pythonhosted.org, port: 443, protocol: tcp }
      - { host: registry.npmjs.org, port: 443, protocol: tcp }
      - { host: crates.io, port: 443, protocol: tcp }
      - { host: docs.python.org, port: 443, protocol: tcp }
      - { host: speed.cloudflare.com, port: 443, protocol: tcp }
    binaries:
      - path: "/**"
"""


def run(command: list[str], **kwargs) -> str:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        **kwargs,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"{' '.join(command[:4])} ... failed (exit {result.returncode}):\n{result.stdout}"
        )
    return result.stdout


def direct_round() -> str:
    env = dict(os.environ, OPENSHELL_LIVE_PERF_MODE="direct")
    return run([sys.executable, str(ROUND)], env=env)


def sandbox_round(openshell: str, name: str, source: str) -> str:
    return run(
        [
            openshell,
            "sandbox",
            "exec",
            "--name",
            name,
            "--no-tty",
            "--",
            "sh",
            "-c",
            'OPENSHELL_LIVE_PERF_MODE=sandbox python3 -c "$1"',
            "openshell-live-internet-perf",
            source,
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--rounds", type=int, default=10, help="rounds per side (default 10)"
    )
    parser.add_argument(
        "--from", dest="image", help="sandbox image (default: the gateway's)"
    )
    parser.add_argument("--openshell", default="openshell", help="openshell CLI to use")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")

    source = ROUND.read_text()
    name = f"live-perf-{uuid.uuid4().hex[:8]}"
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as policy:
        policy.write(POLICY)
        policy.flush()
        create = [
            args.openshell,
            "sandbox",
            "create",
            "--name",
            name,
            "--policy",
            policy.name,
        ]
        if args.image:
            create += ["--from", args.image]
        started = time.perf_counter()
        try:
            run([*create, "--detach"])
            elapsed_ms = (time.perf_counter() - started) * 1000
            print(
                f"LIVE_INTERNET_PERF create {json.dumps({'elapsed_ms': elapsed_ms})}",
                flush=True,
            )
            for number in range(1, args.rounds + 1):
                # Alternate which side goes first so neither always runs on a
                # warmer network.
                sides = [
                    ("direct", direct_round),
                    ("sandbox", lambda: sandbox_round(args.openshell, name, source)),
                ]
                if number % 2 == 0:
                    sides.reverse()
                for mode, round_fn in sides:
                    print(
                        f"LIVE_INTERNET_PERF {mode} round={number} {round_fn().strip()}",
                        flush=True,
                    )
        finally:
            subprocess.run(
                [args.openshell, "sandbox", "delete", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


if __name__ == "__main__":
    main()
