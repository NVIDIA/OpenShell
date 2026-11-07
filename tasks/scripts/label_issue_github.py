# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded, serial GitHub CLI transport; mutation uncertainty is never retried."""
from __future__ import annotations

import json
import random
import re
import subprocess
import threading
import time
from email.utils import parsedate_to_datetime
from functools import partial
from urllib.parse import urlsplit


class GitHubError(subprocess.CalledProcessError):
    """API failure with recovery metadata and acceptance-checker compatibility."""

    def __init__(self, message, *, status=None, retryable=False, retry_at=None,
                 uncertain_write=False, payload=None):
        super().__init__(1, ["gh", "api"], stderr=f"{message} (HTTP {status})")
        self.status = status
        self.retryable = retryable
        self.retry_at = retry_at
        self.uncertain_write = uncertain_write
        self.payload = payload


def _run_bounded(command, *, input, timeout, output_limit, **_options):
    """Drain both pipes concurrently, killing gh as soon as either exceeds its cap."""
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()

        def drain(stream, key):
            while block := stream.read1(min(65536, output_limit + 1)):
                remaining = output_limit - len(chunks[key])
                chunks[key].extend(block[:max(0, remaining)])
                if len(block) > remaining:
                    overflow.set()
                    process.kill()
                    return

        def feed():
            try:
                if input is not None:
                    process.stdin.write(input.encode("utf-8"))
                    process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()

        workers = [threading.Thread(target=drain, args=(process.stdout, "stdout")),
                   threading.Thread(target=drain, args=(process.stderr, "stderr")),
                   threading.Thread(target=feed)]
        for worker in workers:
            worker.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        finally:
            for worker in workers:
                worker.join()
        if overflow.is_set():
            raise GitHubError("GitHub response exceeds size bound")
        return subprocess.CompletedProcess(command, process.returncode,
                                           chunks["stdout"].decode("utf-8", errors="replace"),
                                           chunks["stderr"].decode("utf-8", errors="replace"))


class GitHubClient:
    """One invocation's shared deadline, pacing, pagination, and telemetry."""

    def __init__(self, *, runner=None, monotonic=time.monotonic,
                 wall_clock=time.time, sleeper=time.sleep, jitter=random.random,
                 request_timeout=30, max_attempts=3, invocation_timeout=300,
                 max_pages=100, max_response_bytes=2 * 1024 * 1024):
        if min(request_timeout, max_attempts, invocation_timeout, max_pages,
               max_response_bytes) <= 0:
            raise ValueError("Transport bounds must be positive")
        self.runner = runner or partial(_run_bounded, output_limit=max_response_bytes)
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.sleeper = sleeper
        self.jitter = jitter
        self.request_timeout = request_timeout
        self.max_attempts = max_attempts
        self.max_pages = max_pages
        self.max_response_bytes = max_response_bytes
        self.started = monotonic()
        self.deadline = self.started + invocation_timeout
        self.last_write = None
        self._diagnostics = {"requests": 0, "retries": 0, "pages": 0,
                             "sleep_seconds": 0}

    @property
    def diagnostics(self):
        return {**self._diagnostics, "elapsed_seconds": self.monotonic() - self.started}

    def __call__(self, path, *, method="GET", data=None, pages=False):
        if pages:
            if method != "GET" or data is not None:
                raise ValueError("Pagination supports GET requests only")
            return self.pages(path)
        return self.request(path, method=method, data=data)

    def _wait(self, delay, *, uncertain_write=False):
        delay = max(0, delay)
        if self.monotonic() + delay >= self.deadline:
            raise GitHubError("Invocation deadline cannot accommodate wait",
                              retryable=True, retry_at=self.wall_clock() + delay,
                              uncertain_write=uncertain_write)
        if delay:
            self.sleeper(delay)
            self._diagnostics["sleep_seconds"] += delay

    @staticmethod
    def _path(path):
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != "https" or parsed.netloc != "api.github.com":
                raise GitHubError("Invalid GitHub pagination URL")
            path = parsed.path.lstrip("/") + ("?" + parsed.query if parsed.query else "")
        if not path or path.startswith("-") or "\n" in path or "\r" in path:
            raise GitHubError("Invalid GitHub API path")
        return path.lstrip("/")

    def _decode(self, result, write):
        raw = result.stdout or ""
        if len(raw.encode("utf-8")) > self.max_response_bytes:
            raise GitHubError("GitHub response exceeds size bound", uncertain_write=write)
        raw = raw.replace("\r\n", "\n")
        status, headers = None, {}
        # gh --include emits the HTTP response status and headers before JSON.
        while raw.startswith("HTTP/"):
            head, separator, raw = raw.partition("\n\n")
            match = re.match(r"HTTP/\S+\s+(\d{3})", head)
            if not separator or not match:
                raise GitHubError("Malformed GitHub response headers", uncertain_write=write)
            status = int(match[1])
            headers = {}
            for line in head.splitlines()[1:]:
                key, colon, value = line.partition(":")
                if not colon:
                    raise GitHubError("Malformed GitHub response header", uncertain_write=write)
                key = key.strip().lower()
                headers[key] = headers.get(key, "") + (", " if key in headers else "") + value.strip()
        try:
            payload = json.loads(raw) if raw.strip() else None
        except (ValueError, TypeError) as exc:
            raise GitHubError("Malformed GitHub JSON response", status=status,
                              uncertain_write=write) from exc
        if status is None:
            raise GitHubError("Missing GitHub HTTP response headers", uncertain_write=write)
        return status, headers, payload

    def _retry_delay(self, headers, attempt, secondary):
        hint = headers.get("retry-after")
        if hint is not None:
            try:
                return max(0, float(hint))
            except ValueError:
                try:
                    return max(0, parsedate_to_datetime(hint).timestamp() - self.wall_clock())
                except (ValueError, TypeError, OverflowError):
                    pass
        if headers.get("x-ratelimit-remaining") == "0":
            try:
                return max(0, float(headers["x-ratelimit-reset"]) - self.wall_clock())
            except (KeyError, ValueError):
                pass
        return max(60 if secondary else 0, 2 ** attempt + min(1, max(0, self.jitter())))

    def request(self, path: str, *, method: str = "GET", data: dict | None = None):
        return self._request(path, method=method, data=data)[0]

    def _request(self, path, *, method="GET", data=None):
        path = self._path(path)
        method = method.upper()
        graphql_read = (path == "graphql" and isinstance(data, dict)
                        and isinstance(data.get("query"), str)
                        and re.match(r"\s*(?:query\b|\{)", data["query"]) is not None
                        and re.search(r"\bmutation\b", data["query"]) is None)
        write = method not in {"GET", "HEAD"} and not graphql_read
        if write and self.last_write is not None:
            self._wait(max(0, 1 - (self.monotonic() - self.last_write)))
        command = ["gh", "api", "--include", "--method", method,
                   "-H", "Accept: application/vnd.github+json", path]
        if data is not None:
            command.extend(["--input", "-"])
        for attempt in range(self.max_attempts):
            remaining = self.deadline - self.monotonic()
            if remaining <= 0:
                raise GitHubError("Invocation deadline exhausted", retryable=True,
                                  retry_at=self.wall_clock())
            self._diagnostics["requests"] += 1
            if write:
                self.last_write = self.monotonic()
            try:
                result = self.runner(command, input=json.dumps(data) if data is not None else None,
                                     capture_output=True, text=True,
                                     timeout=min(self.request_timeout, remaining), check=False)
            except GitHubError as exc:
                exc.uncertain_write = write
                raise
            except (subprocess.TimeoutExpired, OSError) as exc:
                failure = GitHubError("GitHub request failed or timed out", retryable=True,
                                      uncertain_write=write)
                if write or attempt + 1 == self.max_attempts:
                    raise failure from exc
                self._wait(self._retry_delay({}, attempt, False))
                self._diagnostics["retries"] += 1
                continue
            status, headers, payload = self._decode(result, write)
            if path == "graphql" and not isinstance(payload, dict):
                raise GitHubError("Malformed GraphQL response", status=status,
                                  uncertain_write=write)
            graphql_errors = isinstance(payload, dict) and bool(payload.get("errors"))
            if 200 <= status < 300 and not graphql_errors and result.returncode == 0:
                return payload, headers
            message = str(payload.get("message", "")) if isinstance(payload, dict) else ""
            graphql_throttled = False
            if graphql_errors:
                errors = payload["errors"]
                if isinstance(errors, list):
                    message = "; ".join(str(error.get("message", ""))
                                        for error in errors if isinstance(error, dict))
                    graphql_throttled = any(
                        isinstance(error, dict) and error.get("type") == "RATE_LIMITED"
                        for error in errors)
                message = message or "GitHub GraphQL errors"
            secondary = "secondary rate limit" in message.lower() or "abuse detection" in message.lower()
            throttled = graphql_throttled or status == 429 or (status == 403 and (
                secondary or "retry-after" in headers or headers.get("x-ratelimit-remaining") == "0"))
            retryable = throttled or status >= 500
            delay = self._retry_delay(headers, attempt, secondary)
            failure = GitHubError(message or "GitHub API request failed", status=status,
                                  retryable=retryable,
                                  retry_at=self.wall_clock() + delay if retryable else None,
                                  uncertain_write=write, payload=payload)
            if write or not retryable or attempt + 1 == self.max_attempts:
                raise failure
            self._wait(delay)
            self._diagnostics["retries"] += 1
        raise AssertionError("unreachable")

    def pages(self, path: str) -> list:
        result, visited = [], set()
        path = self._path(path)
        for _ in range(self.max_pages):
            if path in visited:
                raise GitHubError("GitHub returned a repeated pagination cursor")
            visited.add(path)
            payload, headers = self._request(path)
            self._diagnostics["pages"] += 1
            if not isinstance(payload, list):
                raise GitHubError("GitHub pagination expected an array")
            result.extend(payload)
            link = headers.get("link", "")
            next_links = re.findall(r'<([^>]*)>\s*;\s*rel="next"', link)
            if not next_links:
                if 'rel="next"' in link:
                    raise GitHubError("Malformed GitHub pagination link")
                return result
            if len(next_links) != 1:
                raise GitHubError("Ambiguous GitHub pagination link")
            path = self._path(next_links[0])
            if path in visited:
                raise GitHubError("GitHub returned a repeated pagination cursor")
        raise GitHubError("GitHub pagination page budget exhausted")
