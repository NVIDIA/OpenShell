# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test native NVIDIA inference with non-streaming and streaming requests.

OpenShell attaches a profile-backed provider to supply endpoint-bound
``NVIDIA_API_KEY`` credentials and matching network policy. The client selects
the native endpoint, model, request shape, and timeout.

Usage:
  openshell sandbox create --provider nvidia-demo --policy sandbox-policy.yaml \
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
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise SystemExit(
            "NVIDIA_API_KEY is unavailable; attach the nvidia-demo provider "
            "and launch a new process"
        )

    client = OpenAI(api_key=api_key, base_url=DIRECT_URL, timeout=300)
    run_non_streaming(client, DIRECT_URL, model=DIRECT_MODEL)
    run_streaming(client, DIRECT_URL, model=DIRECT_MODEL)


if __name__ == "__main__":
    main()
