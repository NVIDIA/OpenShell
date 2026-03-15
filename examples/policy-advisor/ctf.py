#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Policy Advisor CTF  --  Mechanistic Mode

A capture-the-flag challenge that exercises OpenShell's policy recommendation
pipeline.  Run this inside a sandbox with the restrictive policy, then use the
TUI to approve mechanistic recommendations and unlock each gate.

Gate 1 tests the basic HTTPS flow (CONNECT tunnel).
Gate 2 tests plain HTTP (forward proxy path).
Gate 3 uses curl to hit an endpoint only it accesses (per-binary tracking).
Gates 4-6 fire concurrently to test batch approval.

Usage:
    python3 ctf.py            # run all gates
    python3 ctf.py --dry-run  # print gate list without making requests
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime


# -- Terminal formatting -------------------------------------------------------

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

RETRY_INTERVAL = 10  # seconds between retries
MAX_RETRIES = 180  # ~30 minutes max per gate


def log(level: str, msg: str, **kv: object) -> None:
    """Structured log line with timestamp and colour."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    colours = {
        "INFO": BLUE,
        "GATE": CYAN,
        "PASS": GREEN,
        "FAIL": RED,
        "WARN": YELLOW,
        "FLAG": MAGENTA,
    }
    c = colours.get(level, "")
    extra = "  ".join(f"{DIM}{k}={v}{RESET}" for k, v in kv.items())
    print(f"  {DIM}{ts}{RESET}  {c}{level:4}{RESET}  {msg}  {extra}", flush=True)


# -- Gate definitions ----------------------------------------------------------

GATES: list[dict] = [
    # -- Gate 1: HTTPS on 443 (CONNECT tunnel) --------------------------------
    {
        "num": 1,
        "name": "The Ping",
        "host": "httpbin.org",
        "port": 443,
        "url": "https://httpbin.org/get",
        "method": "GET",
        "headers": {"Accept": "application/json"},
        "body": None,
        "hint": "A simple HTTPS echo to prove the CONNECT tunnel works.",
        "extract": lambda d: f"origin = {json.loads(d).get('origin', '?')}",
    },
    # -- Gate 2: plain HTTP on 80 (forward proxy, python) ----------------------
    {
        "num": 2,
        "name": "The Cartographer",
        "host": "ip-api.com",
        "port": 80,
        "url": "http://ip-api.com/json/?fields=status,country,city,query",
        "method": "GET",
        "headers": {},
        "body": None,
        "hint": "Navigate the unencrypted waters of port 80 (python).",
        "extract": lambda d: (
            "{city}, {country} ({query})".format_map(json.loads(d))
            if json.loads(d).get("status") == "success"
            else json.loads(d).get("message", "?")
        ),
    },
    # -- Gate 3: curl-only endpoint (per-binary granularity) -----------------
    {
        "num": 3,
        "name": "The Cartographer's Apprentice",
        "host": "ifconfig.me",
        "port": 80,
        "url": "http://ifconfig.me",
        "method": "GET",
        "headers": {},
        "body": None,
        "hint": "curl charts its own course -- a different endpoint only it can reach.",
        "use_curl": True,
        "extract": lambda d: f"public IP = {d.strip()}",
    },
    # -- Gates 4-6: concurrent HTTPS requests (batch approval) ----------------
    {
        "num": 4,
        "name": "The Oracle",
        "host": "api.github.com",
        "port": 443,
        "url": "https://api.github.com/zen",
        "method": "GET",
        "headers": {
            "User-Agent": "openshell-ctf",
            "Accept": "application/vnd.github+json",
        },
        "body": None,
        "hint": "Ancient wisdom from the code forge.",
        "extract": lambda d: d.strip()[:80],
    },
    {
        "num": 5,
        "name": "The Jester",
        "host": "icanhazdadjoke.com",
        "port": 443,
        "url": "https://icanhazdadjoke.com/",
        "method": "GET",
        "headers": {"Accept": "application/json", "User-Agent": "openshell-ctf"},
        "body": None,
        "hint": "Laughter unlocks the fourth seal.",
        "extract": lambda d: json.loads(d).get("joke", "?")[:120],
    },
    {
        "num": 6,
        "name": "The Sphinx",
        "host": "catfact.ninja",
        "port": 443,
        "url": "https://catfact.ninja/fact",
        "method": "GET",
        "headers": {"Accept": "application/json", "User-Agent": "openshell-ctf"},
        "body": None,
        "hint": "Answer the Sphinx's riddle.",
        "extract": lambda d: json.loads(d).get("fact", "?")[:120],
    },
    # -- Gate 7: HTTPS to internal IP (allowed_ips SSRF override) -------------
    {
        "num": 7,
        "name": "The Vault",
        "host": "internal.corp.example.com",
        "port": 443,
        "url": "https://internal.corp.example.com/",
        "method": "GET",
        "headers": {"User-Agent": "openshell-ctf"},
        "body": None,
        "hint": "Reach behind the firewall -- this host resolves to a private IP.",
        "extract": lambda d: f"page length = {len(d)} bytes",
    },
]


# -- Network request logic ----------------------------------------------------


def _is_proxy_block(exc: Exception) -> bool:
    """Heuristic: did the sandbox proxy reject this connection?"""
    msg = str(exc).lower()
    return any(
        tok in msg
        for tok in ("403", "forbidden", "connection refused", "connection reset")
    )


def attempt_gate_curl(gate: dict) -> tuple[str, str]:
    """Try to pass through a gate using curl as the binary.

    Returns the same tuple convention as ``attempt_gate``.
    """
    try:
        result = subprocess.run(
            ["curl", "-sS", "--max-time", "15", gate["url"]],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0 and result.stdout:
            flag = gate["extract"](result.stdout)
            return "pass", flag
        stderr = result.stderr.strip().lower()
        if any(tok in stderr for tok in ("403", "forbidden", "refused", "reset")):
            return (
                "blocked",
                f"blocked by sandbox proxy (curl: {result.stderr.strip()[:80]})",
            )
        if result.returncode != 0:
            return (
                "blocked",
                f"curl failed (rc={result.returncode}: {result.stderr.strip()[:80]})",
            )
        return "blocked", "curl returned empty response"
    except subprocess.TimeoutExpired:
        return "blocked", "curl timed out"
    except FileNotFoundError:
        return "error", "curl not found in sandbox"
    except Exception as exc:  # noqa: BLE001
        return "error", f"unexpected curl error ({exc})"


def attempt_gate(gate: dict) -> tuple[str, str]:
    """Try to pass through a gate.

    Returns ``("pass", flag)`` on success, ``("blocked", reason)`` when the
    proxy denied the connection (retryable), or ``("error", detail)`` for a
    real upstream failure (not retryable).
    """
    if gate.get("use_curl"):
        return attempt_gate_curl(gate)
    try:
        req = urllib.request.Request(
            gate["url"],
            headers=gate.get("headers") or {},
            method=gate["method"],
        )
        if gate.get("body"):
            req.data = gate["body"].encode("utf-8")

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8")
            flag = gate["extract"](data)
            return "pass", flag

    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return "blocked", "blocked by sandbox proxy (403)"
        return "error", f"HTTP {exc.code} from {gate['host']}"

    except urllib.error.URLError as exc:
        if _is_proxy_block(exc):
            return "blocked", "blocked by sandbox proxy"
        reason = str(exc.reason)
        if "timed out" in reason:
            return "blocked", "connection timed out"
        return "blocked", f"connection failed ({reason})"

    except (ConnectionError, OSError, socket.timeout) as exc:
        if _is_proxy_block(exc):
            return "blocked", "connection refused by proxy"
        return "blocked", f"network error ({exc})"

    except Exception as exc:  # noqa: BLE001
        return "error", f"unexpected error ({exc})"


# -- Banner / victory ----------------------------------------------------------

BANNER = f"""
{CYAN}{BOLD}\
  +============================================================+
  |         POLICY ADVISOR CTF  --  MECHANISTIC MODE           |
  +============================================================+
  |                                                            |
  |  Your sandbox blocks all traffic except api.anthropic.com  |
  |  7 gates stand between you and victory.                    |
  |                                                            |
  |  Gate 1   HTTPS endpoint (CONNECT tunnel)                  |
  |  Gate 2   HTTP endpoint  (forward proxy, python)           |
  |  Gate 3   curl-only endpoint (per-binary granularity)      |
  |  Gate 4-6 Concurrent requests (batch approval)             |
  |  Gate 7   Internal IP endpoint (allowed_ips SSRF override) |
  |                                                            |
  +============================================================+\
{RESET}
"""

VICTORY = f"""
{GREEN}{BOLD}\
  +============================================================+
  |                                                            |
  |              *  ALL 7 GATES UNLOCKED  *                    |
  |                                                            |
  |  You've mastered mechanistic policy recommendations.       |
  |                                                            |
  |  Each denied connection was detected by the sandbox        |
  |  proxy, analyzed by the sandbox-side mechanistic mapper,   |
  |  and submitted to the gateway as a NetworkPolicyRule       |
  |  for your approval.                                        |
  |                                                            |
  +============================================================+\
{RESET}
"""


# -- Dry-run -------------------------------------------------------------------


def dry_run() -> None:
    """Print gate list without making any network requests."""
    print(BANNER)
    log("INFO", "Dry-run mode -- listing gates only")
    print()
    for g in GATES:
        proto = "HTTPS" if g["port"] == 443 else "HTTP"
        concurrent = "  (concurrent)" if 4 <= g["num"] <= 6 else ""
        print(
            f"  {CYAN}Gate {g['num']}{RESET}  "
            f"{BOLD}{g['name']}{RESET}  "
            f"{DIM}{g['host']}:{g['port']}  {g['method']}  {proto}{concurrent}{RESET}"
        )
        print(f"         {DIM}{g['hint']}{RESET}")
        print()
    log("INFO", "Run without --dry-run inside a sandbox to start the challenge")


# -- Sequential gate runner ----------------------------------------------------


def run_gate(gate: dict) -> bool:
    """Run a single gate with retry loop. Returns True on success."""
    num = gate["num"]
    total = len(GATES)

    print(f"  {CYAN}{BOLD}{'=' * 60}{RESET}")
    print(f"  {CYAN}{BOLD}  GATE {num}/{total}:  {gate['name'].upper()}{RESET}")
    proto = "https" if gate["port"] == 443 else "http"
    print(
        f"  {DIM}  {gate['hint']}{RESET}\n"
        f"  {DIM}  target: {proto}://{gate['host']}:{gate['port']}  "
        f"({gate['method']}){RESET}"
    )
    print(f"  {CYAN}{BOLD}{'=' * 60}{RESET}")
    print()

    for attempt in range(1, MAX_RETRIES + 1):
        log(
            "GATE",
            f"Gate {num}  attempt #{attempt}",
            host=gate["host"],
            port=gate["port"],
        )

        status, result = attempt_gate(gate)

        if status == "pass":
            log("PASS", f"Gate {num} UNLOCKED")
            log("FLAG", result)
            print()
            return True

        if status == "error":
            log("WARN", f"Gate {num} skipped: {result}")
            log("INFO", "This is an upstream error, not a proxy block")
            print()
            return True

        log("FAIL", f"Gate {num}: {result}")

        if attempt == 1:
            log("WARN", "Approve the recommendation in the TUI to proceed")
            log(
                "INFO",
                "TUI: select sandbox -> [r] drafts -> [a] approve",
            )

        for remaining in range(RETRY_INTERVAL, 0, -1):
            print(
                f"\r  {DIM}        retrying in {remaining:>2}s ...{RESET}",
                end="",
                flush=True,
            )
            time.sleep(1)
        print("\r" + " " * 50 + "\r", end="", flush=True)

    log("FAIL", f"Gate {num} timed out after {MAX_RETRIES} attempts")
    return False


# -- Concurrent gate runner ----------------------------------------------------


def run_gates_concurrent(gates: list[dict]) -> int:
    """Run multiple gates concurrently, retrying until all pass.

    Returns the number of gates that passed.
    """
    nums = ", ".join(str(g["num"]) for g in gates)
    total = len(GATES)

    print(f"  {CYAN}{BOLD}{'=' * 60}{RESET}")
    print(f"  {CYAN}{BOLD}  GATES {nums} (CONCURRENT):{RESET}")
    for g in gates:
        proto = "https" if g["port"] == 443 else "http"
        print(
            f"  {DIM}  Gate {g['num']}: {g['name']}  "
            f"{proto}://{g['host']}:{g['port']}{RESET}"
        )
    print(f"  {CYAN}{BOLD}{'=' * 60}{RESET}")
    print()

    log(
        "INFO",
        f"Firing {len(gates)} requests concurrently -- approve them all at once",
    )
    log("INFO", "Tip: press [A] in the TUI draft panel to approve all pending")
    print()

    remaining_gates = list(gates)

    for attempt in range(1, MAX_RETRIES + 1):
        log(
            "GATE",
            f"Concurrent attempt #{attempt}",
            pending=len(remaining_gates),
        )

        # Fire all remaining gates concurrently.
        results: dict[int, tuple[str, str]] = {}
        threads: list[threading.Thread] = []

        def _attempt(g: dict) -> None:
            results[g["num"]] = attempt_gate(g)

        for g in remaining_gates:
            t = threading.Thread(target=_attempt, args=(g,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        # Process results.
        still_blocked = []
        for g in remaining_gates:
            num = g["num"]
            status, result = results.get(num, ("blocked", "no result"))

            if status == "pass":
                log("PASS", f"Gate {num}/{total} UNLOCKED ({g['name']})")
                log("FLAG", result)
            elif status == "error":
                log("WARN", f"Gate {num}/{total} skipped: {result}")
            else:
                log("FAIL", f"Gate {num}/{total}: {result}")
                still_blocked.append(g)

        passed = len(remaining_gates) - len(still_blocked)
        if passed > 0:
            print()

        if not still_blocked:
            return len(gates)

        remaining_gates = still_blocked

        if attempt == 1:
            log("WARN", "Approve the recommendations in the TUI to proceed")
            log(
                "INFO",
                "TUI: select sandbox -> [r] drafts -> [A] approve all",
            )

        for secs in range(RETRY_INTERVAL, 0, -1):
            print(
                f"\r  {DIM}        retrying in {secs:>2}s ...{RESET}",
                end="",
                flush=True,
            )
            time.sleep(1)
        print("\r" + " " * 50 + "\r", end="", flush=True)

    failed = len(remaining_gates)
    log("FAIL", f"{failed} gate(s) timed out after {MAX_RETRIES} attempts")
    return len(gates) - failed


# -- Main CTF loop -------------------------------------------------------------


def run_ctf() -> int:
    print(BANNER)

    log("INFO", "Starting CTF challenge", gates=len(GATES))
    log("INFO", f"Retry interval: {RETRY_INTERVAL}s between attempts")
    log(
        "INFO",
        "Tip: open the TUI now if you haven't  ->  openshell term",
    )
    print()

    completed = 0

    # Gate 1: single HTTPS endpoint
    if not run_gate(GATES[0]):
        return 1
    completed += 1

    # Gate 2: HTTP endpoint (python)
    if not run_gate(GATES[1]):
        return 1
    completed += 1

    # Gate 3: same endpoint via curl (per-binary granularity)
    if not run_gate(GATES[2]):
        return 1
    completed += 1

    # Gates 4-6: concurrent
    completed += run_gates_concurrent(GATES[3:6])

    # Gate 7: internal IP endpoint (allowed_ips SSRF override)
    if not run_gate(GATES[6]):
        return 1
    completed += 1

    # Done
    if completed >= len(GATES):
        print(VICTORY)
        log("INFO", "CTF complete", gates_passed=f"{completed}/{len(GATES)}")
        return 0

    log("WARN", f"CTF incomplete: {completed}/{len(GATES)} gates passed")
    return 1


# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    try:
        if "--dry-run" in sys.argv:
            dry_run()
            sys.exit(0)
        sys.exit(run_ctf())
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}CTF interrupted.{RESET}")
        sys.exit(130)
