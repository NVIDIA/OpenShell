#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""One round of the live-Internet benchmark, shaped like a short coding-agent
session. Prints one JSON document. `live_internet_perf.py` runs it on the host
and inside a sandbox; it needs only the Python standard library and, for the
clone step, git.
"""

import concurrent.futures
import http.client
import json
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

MODE = os.environ.get("OPENSHELL_LIVE_PERF_MODE", "direct")
TLS = ssl.create_default_context()
USER_AGENT = "OpenShell-live-Internet-benchmark/1"

METADATA_URLS = [
    "https://raw.githubusercontent.com/NVIDIA/OpenShell/main/README.md",
    "https://pypi.org/pypi/requests/json",
    "https://registry.npmjs.org/typescript/latest",
    "https://docs.python.org/3/",
]
DNS_HOSTS = [
    "github.com",
    "raw.githubusercontent.com",
    "pypi.org",
    "registry.npmjs.org",
    "crates.io",
    "docs.python.org",
    "speed.cloudflare.com",
]


def percentile(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * fraction))]


def request(url, method="GET", max_bytes=None):
    parsed = urllib.parse.urlsplit(url)
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port or 443, timeout=20, context=TLS
    )
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    started = time.perf_counter_ns()
    connection.request(
        method, path, headers={"User-Agent": USER_AGENT, "Connection": "close"}
    )
    response = connection.getresponse()
    first = response.read(1)
    first_byte_ms = (time.perf_counter_ns() - started) / 1_000_000
    body_bytes = len(first)
    while max_bytes is None or body_bytes < max_bytes:
        remaining = None if max_bytes is None else max_bytes - body_bytes
        chunk = response.read(65536 if remaining is None else min(65536, remaining))
        if not chunk:
            break
        body_bytes += len(chunk)
    total_ms = (time.perf_counter_ns() - started) / 1_000_000
    status = response.status
    connection.close()
    if status < 200 or status >= 400:
        raise RuntimeError(f"{url} returned HTTP {status}")
    return {
        "status": status,
        "bytes": body_bytes,
        "first_byte_ms": first_byte_ms,
        "total_ms": total_ms,
    }


def metric(name, operation):
    started = time.perf_counter_ns()
    try:
        detail = operation()
        return {
            "name": name,
            "ok": True,
            "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "detail": detail,
        }
    except Exception as error:
        return {
            "name": name,
            "ok": False,
            "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "error": f"{type(error).__name__}: {error}",
        }


def dns_set():
    samples = []
    for host in DNS_HOSTS:
        started = time.perf_counter_ns()
        addresses = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        samples.append(
            {
                "host": host,
                "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
                "addresses": len(addresses),
            }
        )
    timings = [sample["elapsed_ms"] for sample in samples]
    return {
        "lookups": samples,
        "p50_ms": percentile(timings, 0.50),
        "p95_ms": percentile(timings, 0.95),
    }


def metadata_serial():
    return {"requests": [request(url, max_bytes=2_000_000) for url in METADATA_URLS]}


def metadata_concurrent():
    urls = METADATA_URLS + METADATA_URLS
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda url: request(url, max_bytes=2_000_000), urls))
    return {"requests": responses}


def https_reuse():
    connection = http.client.HTTPSConnection(
        "example.com", 443, timeout=20, context=TLS
    )
    samples = []
    try:
        for _ in range(20):
            started = time.perf_counter_ns()
            connection.request(
                "HEAD",
                "/",
                headers={"User-Agent": USER_AGENT, "Connection": "keep-alive"},
            )
            response = connection.getresponse()
            response.read()
            if response.status != 200:
                raise RuntimeError(f"example.com returned HTTP {response.status}")
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
    finally:
        connection.close()
    return {
        "requests": len(samples),
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "mean_ms": statistics.fmean(samples),
    }


def git_clone():
    if shutil.which("git") is None:
        return {"skipped": "git is not installed in the workload image"}
    with tempfile.TemporaryDirectory(prefix="openshell-live-git-") as directory:
        checkout = Path(directory) / "sampleproject"
        command = [
            "git",
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--filter=blob:none",
            "https://github.com/pypa/sampleproject.git",
            str(checkout),
        ]
        output = subprocess.run(
            command,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if output.returncode != 0:
            raise RuntimeError(output.stderr.decode(errors="replace")[-500:])
        paths = [path for path in checkout.rglob("*") if path.is_file()]
        files = len(paths)
        size = sum(path.stat().st_size for path in paths)
        return {"files": files, "checkout_bytes": size}


def package_download():
    metadata = request("https://pypi.org/pypi/idna/json", max_bytes=2_000_000)
    connection = http.client.HTTPSConnection("pypi.org", 443, timeout=20, context=TLS)
    connection.request("GET", "/pypi/idna/json", headers={"User-Agent": USER_AGENT})
    response = connection.getresponse()
    document = json.loads(response.read())
    connection.close()
    wheels = [
        entry for entry in document["urls"] if entry["packagetype"] == "bdist_wheel"
    ]
    if not wheels:
        raise RuntimeError("PyPI returned no idna wheel")
    artifact = request(wheels[0]["url"], max_bytes=5_000_000)
    return {
        "metadata": metadata,
        "artifact": artifact,
        "filename": wheels[0]["filename"],
    }


def bulk_download():
    return request(
        "https://speed.cloudflare.com/__down?bytes=5242880", max_bytes=5242880
    )


def denied_destination():
    if MODE != "sandbox":
        return {"skipped": "policy denial applies only to sandbox mode"}
    started = time.perf_counter_ns()
    try:
        socket.create_connection(("example.net", 443), timeout=5).close()
    except OSError as error:
        return {
            "denied": True,
            "latency_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "error": str(error),
        }
    raise RuntimeError("destination omitted from policy was reachable")


started = time.perf_counter_ns()
metrics = [
    metric("dns_service_set", dns_set),
    metric("https_metadata_serial", metadata_serial),
    metric("https_metadata_concurrent", metadata_concurrent),
    metric("https_reuse", https_reuse),
    metric("git_clone", git_clone),
    metric("package_download", package_download),
    metric("bulk_download_5mib", bulk_download),
    metric("policy_denial", denied_destination),
]
document = {
    "schema": "openshell.live-internet-perf.v1",
    "mode": MODE,
    "total_ms": (time.perf_counter_ns() - started) / 1_000_000,
    "metrics": metrics,
}
print(json.dumps(document, separators=(",", ":")))
if any(item["name"] == "policy_denial" and not item["ok"] for item in metrics):
    raise SystemExit(1)
