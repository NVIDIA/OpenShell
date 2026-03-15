<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy Advisor CTF -- Mechanistic Mode

A capture-the-flag challenge that walks you through OpenShell's policy
recommendation pipeline.  You start with a sandbox that only allows traffic to
`api.anthropic.com`.  A Python script tries to reach 7 endpoints -- and fails.
The sandbox proxy detects each denial, the sandbox-side mechanistic mapper
turns it into a concrete `NetworkPolicyRule` proposal, and submits it to the
gateway for your approval.  You approve those recommendations in the TUI, and
the script progresses through each gate.

## How It Works

1. **Script makes a request** -- the sandbox proxy blocks it and emits a
   `DenialEvent`.
2. **DenialAggregator batches events** -- every ~10 seconds it drains
   aggregated denial summaries.
3. **Mechanistic mapper generates proposals (sandbox-side)** -- each unique
   `(host, port, binary)` triple becomes a `PolicyChunk` with a proposed
   `NetworkPolicyRule`, confidence score, and rationale.  If the host resolves
   to a private IP, the mapper includes `allowed_ips` for the SSRF override.
4. **Proposals submitted to gateway** -- via `SubmitPolicyAnalysis`.  The
   gateway validates and persists the proposals.
5. **TUI shows recommendations** -- navigate to the sandbox's rules panel to
   see pending proposals.
6. **You approve** -- the approved rule merges into the active sandbox policy
   and the proxy begins allowing the connection.
7. **Script retries and succeeds** -- on to the next gate.

## Files

| File | Description |
|---|---|
| `sandbox-policy.yaml` | Restrictive policy that only allows `api.anthropic.com:443` |
| `ctf.py` | Python script with 7 network gates |
| `README.md` | This walkthrough |

## Gates

| # | Name | Target | Notes |
|---|---|---|---|
| 1 | The Ping | `httpbin.org:443` | HTTPS (CONNECT tunnel path) |
| 2 | The Cartographer | `ip-api.com:80` | Plain HTTP via python (forward proxy path) |
| 3 | The Cartographer's Apprentice | `ifconfig.me:80` | curl-only endpoint (per-binary granularity) |
| 4 | The Oracle | `api.github.com:443` | Concurrent with 5 and 6 |
| 5 | The Jester | `icanhazdadjoke.com:443` | Concurrent with 4 and 6 |
| 6 | The Sphinx | `catfact.ninja:443` | Concurrent with 4 and 5 |
| 7 | The Vault | `internal.corp.example.com:443` | Internal IP -- mapper adds `allowed_ips` |

Gates 1-3 run sequentially so you can observe the single-approval flow.
Gate 3 uses `curl` to hit `ifconfig.me:80` -- a different endpoint that only
curl accesses.  Because the proxy tracks the originating binary, curl's denial
produces its own `(host, port, binary)` rule separate from python's rules.
(Note: OPA's ancestor matching lets child processes inherit their parent's
network access -- curl spawned by python would share python's approvals for the
same endpoint.  Gate 3 uses a distinct endpoint to clearly demonstrate
per-binary tracking in the TUI.)
Gates 4-6 fire concurrently so all three denials arrive together -- use
`[A]` (approve all) in the TUI to unlock them in one shot.
Gate 7 targets a host that resolves to a private IP.  The mechanistic mapper
detects this and includes `allowed_ips` in the proposed rule so the proxy's
SSRF override allows the connection.

## Quick Start

### Prerequisites

- A running OpenShell gateway (`openshell gateway start` or a remote gateway)
- The `openshell` CLI installed
- Two terminal windows

### 1. Open the TUI

In your **first terminal**, launch the interactive TUI so you can watch
denials arrive and approve recommendations:

```bash
openshell term
```

### 2. Create the sandbox and run the CTF

In your **second terminal**, create the sandbox with the restrictive policy,
upload the script, and run it -- all in one command:

```bash
openshell sandbox create \
  --name advisor-ctf \
  --policy examples/policy-advisor/sandbox-policy.yaml \
  --upload examples/policy-advisor/ctf.py \
  --keep \
  -- python3 -u /sandbox/ctf.py
```

> **For agents running this CTF:** use the command above exactly.  The
> `--upload` flag copies the script into `/sandbox/` before the command runs,
> `--keep` prevents the sandbox from being torn down on exit, and `-u` gives
> unbuffered output so you can see logs in real time.

The script prints a banner and immediately tries Gate 1 (`httpbin.org:443`).
It will fail with **"blocked by sandbox proxy"** and begin retrying every 10
seconds.

### 3. Approve recommendations in the TUI

Switch to the TUI terminal.  Within ~10 seconds you should see the sandbox
reporting denial activity.

1. **Select the sandbox** -- use arrow keys to highlight `advisor-ctf` and
   press `Enter`.
2. **Open the draft recommendations panel** -- press `r`.
3. **Approve a recommendation** -- highlight the pending chunk for
   `httpbin.org:443` and press `a` to approve it.

The policy update propagates to the sandbox within seconds.  On the next retry
the script passes Gate 1 and moves on to Gate 2.

Gate 3 uses `curl` to reach `ifconfig.me:80`.  You'll see a new rule for
`ifconfig.me:80` with `curl` as the binary.  Approve it to proceed.

When Gates 4-6 start, all three denials arrive together.  Press `A` to approve
all pending recommendations at once.

Gate 7 requires `allowed_ips` because `internal.corp.example.com` resolves to a
private IP.  The mapper detects this automatically and includes the resolved IPs
in the proposed rule.

### 4. Win

Once all 7 gates are unlocked the script prints a victory banner.

## Tips

- **Dry run** -- run `python3 ctf.py --dry-run` to see the gate list without
  making any network requests.
- **Flush interval** -- the denial aggregator flushes every 10 seconds by
  default.  Set `OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS=5` in the sandbox
  environment for faster feedback during the demo.
- **CLI alternative** -- you can approve drafts from the CLI instead of the
  TUI:
  ```bash
   openshell rule get advisor-ctf                    # list pending
   openshell rule approve advisor-ctf --chunk-id ID  # approve one
   openshell rule approve-all advisor-ctf             # approve all
  ```
- **Gate 3 shows per-binary tracking** -- curl hits its own endpoint, producing
  a rule attributed to `curl` rather than `python3` in the TUI.
- **Gate 7 is different** -- it targets a host that resolves to a private IP.
  The mapper automatically adds `allowed_ips` so the proxy's SSRF override
  permits the connection.

## Cleanup

```bash
openshell sandbox delete advisor-ctf
```
