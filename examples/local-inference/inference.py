# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test inference routing through inference.local (streaming and non-streaming).

Exercises both modes to surface the response-buffering bug where the proxy
calls response.bytes().await on a streaming response, inflating TTFB from
sub-second to the full generation time.
"""

import subprocess
import sys
import time

subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "openai"])

from openai import OpenAI  # noqa: E402

client = OpenAI(api_key="dummy", base_url="https://inference.local/v1")

PROMPT = "Write a short haiku about computers."
MESSAGES = [{"role": "user", "content": PROMPT}]


def test_non_streaming():
    print("=" * 60)
    print("NON-STREAMING REQUEST")
    print("=" * 60)

    t0 = time.monotonic()
    response = client.chat.completions.create(
        model="router",
        messages=MESSAGES,
        temperature=0,
    )
    elapsed = time.monotonic() - t0

    content = (response.choices[0].message.content or "").strip()
    print(f"  model   = {response.model}")
    print(f"  content = {content}")
    print(f"  total   = {elapsed:.2f}s")
    print()


def test_streaming():
    print("=" * 60)
    print("STREAMING REQUEST")
    print("=" * 60)

    t0 = time.monotonic()
    ttfb = None
    chunks = []

    stream = client.chat.completions.create(
        model="router",
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

    print(f"  model   = {chunk.model}")
    print(f"  content = {content}")
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


if __name__ == "__main__":
    test_non_streaming()
    test_streaming()
