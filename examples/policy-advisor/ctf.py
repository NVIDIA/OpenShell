#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Policy Advisor CTF  --  Mechanistic Mode

A capture-the-flag challenge that exercises OpenShell's policy recommendation
pipeline.  Run this inside a sandbox with the restrictive policy, then use the
TUI to approve mechanistic recommendations and unlock each gate.

Every gate makes a network call to a public service.  The sandbox proxy blocks
the call, the DenialAggregator reports it to the gateway, and the mechanistic
mapper generates a policy recommendation.  Approve it in the TUI and the next
retry succeeds.

Usage:
    python3 ctf.py            # run all gates
    python3 ctf.py --dry-run  # print gate list without making requests
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime


# ── Terminal formatting ──────────────────────────────────────────────────────

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


# ── Gate definitions ─────────────────────────────────────────────────────────
#
# Each gate targets a different public endpoint.  The variety exercises the
# mechanistic mapper across hosts, ports, and HTTP methods.
#
#   Gates 1-5 : HTTPS on port 443  (CONNECT tunnel path)
#   Gate 6    : plain HTTP on port 80  (forward-proxy path)
#   Gate 7    : HTTPS on port 443  (final gate)

GATES: list[dict] = [
    # ── Gate 1 ───────────────────────────────────────────────────
    {
        "num": 1,
        "name": "The Ping",
        "host": "httpbin.org",
        "port": 443,
        "url": "https://httpbin.org/get",
        "method": "GET",
        "headers": {"Accept": "application/json"},
        "body": None,
        "hint": "A simple echo to prove you're alive.",
        "extract": lambda d: f"origin = {json.loads(d).get('origin', '?')}",
    },
    # ── Gate 2 ───────────────────────────────────────────────────
    {
        "num": 2,
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
    # ── Gate 3 ───────────────────────────────────────────────────
    {
        "num": 3,
        "name": "The Jester",
        "host": "icanhazdadjoke.com",
        "port": 443,
        "url": "https://icanhazdadjoke.com/",
        "method": "GET",
        "headers": {"Accept": "application/json", "User-Agent": "openshell-ctf"},
        "body": None,
        "hint": "Laughter unlocks the third seal.",
        "extract": lambda d: json.loads(d).get("joke", "?")[:120],
    },
    # ── Gate 4 ───────────────────────────────────────────────────
    {
        "num": 4,
        "name": "The Scribe",
        "host": "jsonplaceholder.typicode.com",
        "port": 443,
        "url": "https://jsonplaceholder.typicode.com/posts",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        "body": json.dumps(
            {
                "title": "CTF Gate 4",
                "body": "The scribe records your passage.",
                "userId": 1,
            }
        ),
        "hint": "Leave your mark -- POST, don't just GET.",
        "extract": lambda d: f"created post id = {json.loads(d).get('id', '?')}",
    },
    # ── Gate 5 ───────────────────────────────────────────────────
    {
        "num": 5,
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
    # ── Gate 6 ───────────────────────────────────────────────────
    # Plain HTTP on port 80 -- exercises the forward-proxy deny path
    # instead of the CONNECT tunnel path used by HTTPS.
    {
        "num": 6,
        "name": "The Cartographer",
        "host": "ip-api.com",
        "port": 80,
        "url": "http://ip-api.com/json/?fields=status,country,city,query",
        "method": "GET",
        "headers": {},
        "body": None,
        "hint": "Navigate the unencrypted waters of port 80.",
        "extract": lambda d: (
            "{city}, {country} ({query})".format_map(json.loads(d))
            if json.loads(d).get("status") == "success"
            else json.loads(d).get("message", "?")
        ),
    },
    # ── Gate 7 ───────────────────────────────────────────────────
    {
        "num": 7,
        "name": "The Guardian",
        "host": "dog.ceo",
        "port": 443,
        "url": "https://dog.ceo/api/breeds/image/random",
        "method": "GET",
        "headers": {"Accept": "application/json"},
        "body": None,
        "hint": "The final guardian reveals its true form.",
        "extract": lambda d: _extract_breed(json.loads(d).get("message", "")),
    },
]


def _extract_breed(url: str) -> str:
    """Pull the breed name out of a dog.ceo image URL."""
    # URL pattern: https://images.dog.ceo/breeds/<breed>/image.jpg
    parts = url.split("/")
    try:
        idx = parts.index("breeds")
        return parts[idx + 1].replace("-", " ").title()
    except (ValueError, IndexError):
        return url


# ── Network request logic ────────────────────────────────────────────────────


def _is_proxy_block(exc: Exception) -> bool:
    """Heuristic: did the sandbox proxy reject this connection?"""
    msg = str(exc).lower()
    return any(
        tok in msg
        for tok in ("403", "forbidden", "connection refused", "connection reset")
    )


def attempt_gate(gate: dict) -> tuple[str, str]:
    """Try to pass through a gate.

    Returns ``("pass", flag)`` on success, ``("blocked", reason)`` when the
    proxy denied the connection (retryable), or ``("error", detail)`` for a
    real upstream failure (not retryable).
    """
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
        # A real HTTP error from the upstream service — not retryable.
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


# ── Banner / victory ─────────────────────────────────────────────────────────

BANNER = f"""
{CYAN}{BOLD}\
  ╔════════════════════════════════════════════════════════════╗
  ║         POLICY ADVISOR CTF  --  MECHANISTIC MODE          ║
  ╠════════════════════════════════════════════════════════════╣
  ║                                                           ║
  ║  Your sandbox blocks all traffic except api.anthropic.com ║
  ║  7 gates stand between you and victory.                   ║
  ║                                                           ║
  ║  Each gate needs a network call to a public service.      ║
  ║  Approve the policy recommendations in the TUI to         ║
  ║  unlock each gate, one by one.                            ║
  ║                                                           ║
  ╚════════════════════════════════════════════════════════════╝\
{RESET}
"""

VICTORY = f"""
{GREEN}{BOLD}\
  ╔════════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║              *  ALL 7 GATES UNLOCKED  *                   ║
  ║                                                           ║
  ║  You've mastered mechanistic policy recommendations.      ║
  ║                                                           ║
  ║  Each denied connection was detected by the sandbox       ║
  ║  proxy, aggregated into a denial summary, transported     ║
  ║  to the gateway, and mapped into a NetworkPolicyRule      ║
  ║  for your approval.                                       ║
  ║                                                           ║
  ║  Next up: AI-assisted mode (issue #205).                  ║
  ║                                                           ║
  ╚════════════════════════════════════════════════════════════╝\
{RESET}
"""


# ── Dry-run ──────────────────────────────────────────────────────────────────


def dry_run() -> None:
    """Print gate list without making any network requests."""
    print(BANNER)
    log("INFO", "Dry-run mode -- listing gates only")
    print()
    for g in GATES:
        proto = "HTTPS" if g["port"] == 443 else "HTTP"
        print(
            f"  {CYAN}Gate {g['num']}{RESET}  "
            f"{BOLD}{g['name']}{RESET}  "
            f"{DIM}{g['host']}:{g['port']}  {g['method']}  {proto}{RESET}"
        )
        print(f"         {DIM}{g['hint']}{RESET}")
        print()
    log("INFO", "Run without --dry-run inside a sandbox to start the challenge")


# ── Main CTF loop ────────────────────────────────────────────────────────────


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

    for gate in GATES:
        num = gate["num"]
        total = len(GATES)

        # Gate header
        print(f"  {CYAN}{BOLD}{'─' * 60}{RESET}")
        print(f"  {CYAN}{BOLD}  GATE {num}/{total}:  {gate['name'].upper()}{RESET}")
        proto = "https" if gate["port"] == 443 else "http"
        print(
            f"  {DIM}  {gate['hint']}{RESET}\n"
            f"  {DIM}  target: {proto}://{gate['host']}:{gate['port']}  "
            f"({gate['method']}){RESET}"
        )
        print(f"  {CYAN}{BOLD}{'─' * 60}{RESET}")
        print()

        # Retry loop
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
                completed += 1
                print()
                break

            if status == "error":
                # Real upstream failure — not a proxy block. Skip the gate
                # so the demo doesn't stall on a flaky third-party service.
                log("WARN", f"Gate {num} skipped: {result}")
                log("INFO", "This is an upstream error, not a proxy block")
                completed += 1
                print()
                break

            # status == "blocked" — proxy denied the connection; retryable.
            log("FAIL", f"Gate {num}: {result}")

            if attempt == 1:
                log("WARN", "Approve the recommendation in the TUI to proceed")
                log(
                    "INFO",
                    "TUI: select sandbox -> [p] policy -> [r] drafts -> [a] approve",
                )

            # Countdown before retry
            for remaining in range(RETRY_INTERVAL, 0, -1):
                print(
                    f"\r  {DIM}        retrying in {remaining:>2}s ...{RESET}",
                    end="",
                    flush=True,
                )
                time.sleep(1)
            # Clear the countdown line
            print("\r" + " " * 50 + "\r", end="", flush=True)

        else:
            log(
                "FAIL",
                f"Gate {num} timed out after {MAX_RETRIES} attempts",
            )
            log(
                "WARN",
                "Check that the gateway is running and the TUI is connected.",
            )
            return 1

    # All gates passed
    print(VICTORY)
    log("INFO", "CTF complete", gates_passed=f"{completed}/{len(GATES)}")
    return 0


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        if "--dry-run" in sys.argv:
            dry_run()
            sys.exit(0)
        sys.exit(run_ctf())
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}CTF interrupted.{RESET}")
        sys.exit(130)
