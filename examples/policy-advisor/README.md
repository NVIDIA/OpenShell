<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy Advisor CTF -- Mechanistic Mode

A capture-the-flag challenge that walks you through OpenShell's policy
recommendation pipeline.  You start with a sandbox that only allows traffic to
`api.anthropic.com`.  A Python script tries to reach 7 public endpoints -- and
fails.  The sandbox proxy detects each denial, aggregates it, and sends it to
the gateway where the mechanistic mapper turns it into a concrete
`NetworkPolicyRule` recommendation.  You approve those recommendations one by
one in the TUI, and the script progresses through each gate.

## How It Works

1. **Script makes a request** -- the sandbox proxy blocks it and emits a
   `DenialEvent`.
2. **DenialAggregator batches events** -- every ~30 seconds it flushes denial
   summaries to the gateway via `SubmitPolicyAnalysis`.
3. **Mechanistic mapper generates proposals** -- each unique `(host, port)`
   pair becomes a `PolicyChunk` with a proposed `NetworkPolicyRule`, confidence
   score, and rationale.
4. **TUI shows recommendations** -- navigate to the sandbox's draft panel to
   see pending proposals.
5. **You approve** -- the approved rule merges into the active sandbox policy
   and the proxy begins allowing the connection.
6. **Script retries and succeeds** -- on to the next gate.

## Files

| File | Description |
|---|---|
| `sandbox-policy.yaml` | Restrictive policy that only allows `api.anthropic.com:443` |
| `ctf.py` | Python script with 7 sequential network gates to public services |
| `README.md` | This walkthrough |

## Gates

| # | Name | Target | Notes |
|---|---|---|---|
| 1 | The Ping | `httpbin.org:443` | HTTPS echo service |
| 2 | The Oracle | `api.github.com:443` | GitHub zen quotes |
| 3 | The Jester | `icanhazdadjoke.com:443` | Random dad joke |
| 4 | The Scribe | `jsonplaceholder.typicode.com:443` | POST request (not just GETs) |
| 5 | The Sphinx | `catfact.ninja:443` | Cat facts |
| 6 | The Cartographer | `ip-api.com:80` | Plain HTTP on port 80 (forward-proxy path) |
| 7 | The Guardian | `dog.ceo:443` | Random dog breed |

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

Switch to the TUI terminal.  Within ~30 seconds you should see the sandbox
reporting denial activity.

1. **Select the sandbox** -- use arrow keys to highlight `advisor-ctf` and
   press `Enter`.
2. **Open the policy view** -- press `p`.
3. **Open the draft recommendations panel** -- press `r`.
4. **Approve a recommendation** -- highlight the pending chunk for
   `httpbin.org:443` and press `a` to approve it.

The policy update propagates to the sandbox immediately.  On the next retry
the script passes Gate 1 and moves on to Gate 2.

Repeat for each gate.  You can also press `A` to approve all pending
recommendations at once if you want to skip ahead.

### 4. Win

Once all 7 gates are unlocked the script prints a victory banner.

## Tips

- **Dry run** -- run `python3 ctf.py --dry-run` to see the gate list without
  making any network requests.
- **Flush interval** -- the denial aggregator flushes every 30 seconds by
  default.  Set `OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS=5` in the sandbox
  environment for faster feedback during the demo.
- **CLI alternative** -- you can approve drafts from the CLI instead of the
  TUI:
  ```bash
  openshell draft get advisor-ctf                    # list pending
  openshell draft approve advisor-ctf --chunk-id ID  # approve one
  openshell draft approve-all advisor-ctf             # approve all
  ```
- **Gate 6 is different** -- it uses plain HTTP on port 80, which exercises
  the forward-proxy deny path instead of the CONNECT tunnel used by HTTPS.
  This generates a separate recommendation with port 80.

## Cleanup

```bash
openshell sandbox delete advisor-ctf
```
