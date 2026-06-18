from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from resolve_licenses import _rate_limit, _last_request, _rate_lock


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
    for a, b in zip(times, times[1:]):
        assert b - a >= interval * 0.9, f"gap {b - a:.4f}s < interval {interval}s"


def test_different_domains_do_not_block_each_other() -> None:
    domains = ["alpha.example", "beta.example"]
    interval = 0.1
    for d in domains:
        with _rate_lock:
            _last_request.pop(d, None)

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda d: _rate_limit(d, interval=interval), domains))
    elapsed = time.monotonic() - start

    assert elapsed < interval * 1.5, f"different-domain calls blocked: {elapsed:.3f}s"


if __name__ == "__main__":
    test_same_domain_requests_are_spaced()
    print("same-domain spacing: ok")
    test_different_domains_do_not_block_each_other()
    print("different-domain non-blocking: ok")
