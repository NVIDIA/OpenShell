# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test inference routing through both inference.local and direct endpoint access.

Exercises four scenarios to verify streaming works correctly:
  1. inference.local — non-streaming
  2. inference.local — streaming
  3. Direct NVIDIA endpoint (L7 TLS intercept) — non-streaming
  4. Direct NVIDIA endpoint (L7 TLS intercept) — streaming

The direct endpoint tests verify that the L7 REST relay path (relay_chunked /
relay_until_eof) streams responses incrementally, in contrast with the
inference.local interception path which previously buffered the entire body.

Usage:
  # inference.local only (no provider attached):
  openshell sandbox create --policy sandbox-policy.yaml --upload inference.py \
    -- python3 /sandbox/inference.py

  # All 4 tests (attach the nvidia provider so NVIDIA_API_KEY is available):
  openshell sandbox create --provider nvidia --policy sandbox-policy.yaml \
    --upload inference.py -- python3 /sandbox/inference.py
"""

import os
import subprocess
import sys
import time

subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "openai"])

from openai import OpenAI  # noqa: E402

PROMPT = (
    "Write a 500-word essay on the history of computing, "
    "from Charles Babbage's Analytical Engine to modern GPUs."
)
MESSAGES = [{"role": "user", "content": PROMPT}]


def run_non_streaming(client: OpenAI, label: str, model: str) -> None:
    print("=" * 60)
    print(f"NON-STREAMING — {label}")
    print("=" * 60)

    t0 = time.monotonic()
    response = client.chat.completions.create(
        model=model,
        messages=MESSAGES,
        temperature=0,
    )
    elapsed = time.monotonic() - t0

    content = (response.choices[0].message.content or "").strip()
    words = content.split()
    print(f"  model   = {response.model}")
    print(f"  words   = {len(words)}")
    print(f"  preview = {' '.join(words[:20])}...")
    print(f"  total   = {elapsed:.2f}s")
    print()


def run_streaming(client: OpenAI, label: str, model: str) -> None:
    print("=" * 60)
    print(f"STREAMING — {label}")
    print("=" * 60)

    t0 = time.monotonic()
    ttfb = None
    chunks = []

    stream = client.chat.completions.create(
        model=model,
        messages=MESSAGES,
        temperature=0,
        stream=True,
    )

    for chunk in stream:
        if ttfb is None:
            ttfb = time.monotonic() - t0
            print(f"  TTFB    = {ttfb:.2f}s")

        delta = chunk.choices[0].delta if chunk.choices else None
        if delta and delta.content:
            chunks.append(delta.content)

    elapsed = time.monotonic() - t0
    content = "".join(chunks).strip()

    words = content.split()
    print(f"  model   = {chunk.model}")
    print(f"  words   = {len(words)}")
    print(f"  preview = {' '.join(words[:20])}...")
    print(f"  total   = {elapsed:.2f}s")
    print()

    # Flag the bug: if TTFB is close to total time, response was buffered.
    if ttfb and elapsed > 0.5 and ttfb > elapsed * 0.8:
        print(
            "  ** BUG: TTFB is {:.0f}% of total time — response was buffered, not streamed **".format(
                ttfb / elapsed * 100
            )
        )
    elif ttfb and ttfb < 2.0:
        print("  OK: TTFB looks healthy (sub-2s)")
    print()


DIRECT_URL = "https://integrate.api.nvidia.com/v1"
DIRECT_MODEL = "meta/llama-3.1-8b-instruct"


def main() -> None:
    # --- inference.local tests (router injects auth + model) ---
    local_client = OpenAI(api_key="dummy", base_url="https://inference.local/v1")

    run_non_streaming(local_client, "inference.local", model="router")
    run_streaming(local_client, "inference.local", model="router")

    # --- Direct endpoint tests (L7 TLS intercept path) ---
    # The API key is available when the sandbox is started with --provider nvidia.
    api_key = os.environ.get("NVIDIA_API_KEY")
    if api_key:
        direct_client = OpenAI(api_key=api_key, base_url=DIRECT_URL)

        run_non_streaming(direct_client, f"direct ({DIRECT_URL})", model=DIRECT_MODEL)
        run_streaming(direct_client, f"direct ({DIRECT_URL})", model=DIRECT_MODEL)
    else:
        print("=" * 60)
        print("SKIPPED — direct endpoint tests (NVIDIA_API_KEY not set)")
        print("=" * 60)
        print("  Attach the nvidia provider to enable: --provider nvidia")
        print()


if __name__ == "__main__":
    main()
