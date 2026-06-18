# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from resolve_licenses import _last_request, _rate_limit, _rate_lock


def test_same_domain_requests_are_spaced() -> None:
    domain = "test.same-domain.example"
    with _rate_lock:
        _last_request.pop(domain, None)

    interval = 0.05
    times: list[float] = []

    def call() -> None:
        _rate_limit(domain, interval=interval)
        times.append(time.monotonic())

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: call(), range(3)))

    times.sort()
    for a, b in itertools.pairwise(times):
        assert b - a >= interval * 0.9, f"gap {b - a:.4f}s < interval {interval}s"


def test_different_domains_do_not_block_each_other() -> None:
    alpha = "alpha2.example"
    beta = "beta2.example"
    interval = 0.1

    now = time.monotonic()
    with _rate_lock:
        _last_request[alpha] = now  # alpha must sleep for ~interval
        _last_request.pop(beta, None)  # beta is free

    ready = threading.Event()

    def call_alpha() -> None:
        ready.set()
        _rate_limit(alpha, interval=interval)

    t = threading.Thread(target=call_alpha)
    t.start()
    ready.wait()
    time.sleep(0.01)  # let alpha enter its sleep

    beta_start = time.monotonic()
    _rate_limit(beta, interval=interval)
    beta_elapsed = time.monotonic() - beta_start

    t.join()

    assert beta_elapsed < interval * 0.5, f"beta blocked for {beta_elapsed:.3f}s"


if __name__ == "__main__":
    test_same_domain_requests_are_spaced()
    print("same-domain spacing: ok")
    test_different_domains_do_not_block_each_other()
    print("different-domain non-blocking: ok")
