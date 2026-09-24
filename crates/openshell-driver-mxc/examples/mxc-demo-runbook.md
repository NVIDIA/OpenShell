# OpenShell MXC demo — runbook

You are running this on the **demo Windows 11 host**. Everything in this folder
was built off-box; nothing here requires `cargo`/`rustc`/`mise`/Visual Studio
on the demo machine.

The proof is **filesystem-policy enforcement**: an agent run by the MXC driver
writes `hello.txt` into a granted host folder (positive) and is denied a write to
any other path (negative).

> **Backend matters.** The driver has two backends, set by `backend` in
> `mxc-gateway.toml` (or `run-demo.ps1 -Backend`):
>
> - **`process_container`** — one-shot AppContainer, **default-deny**. The
>   negative proof (out-of-policy write denied) only holds here. **Use this.**
> - **`isolation_session`** (default) — persistent, but **grant-only / NOT
>   default-deny**: an out-of-policy write can still succeed. Good for the
>   positive proof and persistent-session demos; it cannot prove denial.
>
> This runbook's enforcement steps assume `backend = "process_container"`.

---

## Pre-flight — check the machine FIRST (the known blocker)

These are the only things the operator cannot fix from the package. If any
fails, stop and escalate to the MXC team — it's a machine-provisioning
problem, not a binaries problem.

1. **Windows 11 build ≥ 26300.8553 (Insider).** Required for `isolation_session`.

   ```powershell
   [System.Environment]::OSVersion.Version
   # Major=10  Minor=0  Build=26300  Revision >= 8553 (or any later 263xx)
   ```

   Below this build → no isolation session, demo cannot run on this box.
   Confirm the current required build number with the MXC team before the
   demo; the Insider channel moves.

2. **Velocity keys / feature flags ON for isolation_session.** Per the MXC
   provisioning checklist. The MXC team owns the exact key list — confirm
   before demo day.

3. **`wxc-exec.exe` (with the `isolation_session` feature) is on the box.**
   The OpenShell driver does not bundle `wxc-exec` — it must already live on
   the demo machine. Smoke-test it standalone before involving OpenShell:

   ```powershell
   $env:OPENSHELL_WXC_EXEC_PATH = "C:\path\to\wxc-exec.exe"
   & $env:OPENSHELL_WXC_EXEC_PATH --version
   ```

   If `--version` errors, OpenShell will not save you. Resolve `wxc-exec`
   first.

4. **`IsoSessionApp.dll` present/registered.** Bundled with the Windows
   Insider build; surface if missing via `wxc-exec --probe` (or whatever
   the MXC team currently recommends).

If 1–4 are green, the rest of this runbook is mechanical.

---

## What's in this folder

| File | Purpose |
|---|---|
| `openshell-gateway.exe` | The OpenShell gateway (control plane). Runs as a plain console EXE. |
| `openshell.exe` | The OpenShell CLI. |
| `mxc-demo-agent.exe` | The in-sandbox test application. Runs the positive (in-policy) write + read-back AND the negative (out-of-policy, expected-denied) write in one run; exits `0` only when policy is enforced. |
| `libz3.dll` | Runtime dependency of the CLI (`openshell-prover` → `z3-sys`, dynamic link). The gateway does **not** need it. |
| `demo.yaml` | Filesystem policy: read-write `C:/work/openshell-mxc-demo`, everything else default-deny. |
| `mxc-gateway.toml` | Gateway config: `[openshell.drivers.mxc]` table (share_dir, agent_command, etc.). |
| `run-demo.ps1` | One-shot orchestrator: stages the test app, starts the gateway, registers the CLI, creates the sandbox, collects the verdict, prints PASS/FAIL, and cleans up. |
| `mxc-demo-runbook.md` | This file. |

Drop the whole folder anywhere writable; e.g. `C:\openshell-demo\`. The
binaries do not care about cwd.

---

## One-time setup on the box

1. **Create the host share folder** (must match `share_dir` in
   `mxc-gateway.toml` and the `read_write` path in `demo.yaml`):

   ```powershell
   New-Item -ItemType Directory -Force "C:\work\openshell-mxc-demo" | Out-Null
   ```

   **Stage the test app into the share folder.** `agent_command` in
   `mxc-gateway.toml` launches `mxc-demo-agent.exe` from inside the mapped share,
   so copy it there once:

   ```powershell
   Copy-Item .\mxc-demo-agent.exe "C:\work\openshell-mxc-demo\" -Force
   ```

2. **Point the gateway at `wxc-exec.exe`** — edit `mxc-gateway.toml` and
   uncomment / set the `wxc_exec_path` line to the real path:

   ```toml
   wxc_exec_path = "C:\\mxc\\wxc-exec.exe"
   ```

   (Double the backslashes — TOML.)

   **Select the backend.** In the same `[openshell.drivers.mxc]` table, for the
   default-deny enforcement proof:

   ```toml
   backend = "process_container"
   ```

   (Omit it, or set `isolation_session`, for the persistent grant-only backend.
   `run-demo.ps1 -Backend` patches this for you.)

3. **Environment variables for the demo session** (in the same shell you'll
   launch the gateway in):

   ```powershell
   $env:OPENSHELL_DRIVERS         = "mxc"
   $env:OPENSHELL_MXC_SHARE_DIR   = "C:\work\openshell-mxc-demo"
   # OPENSHELL_WXC_EXEC_PATH is not strictly required by the driver (it reads
   # the path from mxc-gateway.toml) but exporting it makes pre-flight smoke
   # tests easier and matches the runbook for the MXC team.
   $env:OPENSHELL_WXC_EXEC_PATH   = "C:\mxc\wxc-exec.exe"
   ```

---

## Launch the gateway (Window 1)

In a PowerShell prompt in the demo folder:

```powershell
.\openshell-gateway.exe --disable-tls --config .\mxc-gateway.toml --log-level info
```

Healthy startup logs look like:

```
WARN  TLS disabled — listening on plaintext HTTP
INFO  Starting OpenShell server bind=127.0.0.1:17670
INFO  Using compute driver driver=mxc
INFO  Server listening address=127.0.0.1:17670
INFO  TLS disabled — accepting plaintext connections
```

If the gateway exits with a config error, it will name the offending field
(`[openshell.drivers.mxc]`). Fix it in `mxc-gateway.toml` and relaunch.

SQLite lands at `%LOCALAPPDATA%\openshell\gateway\openshell.db` by default;
override with `--db-url` if needed.

Leave this window open — it streams the driver's logs (provision, start,
exec, denial events).

---

## Register the gateway with the CLI (Window 2, once)

The CLI talks to a **registered gateway by name**. The CLI has **no**
`--compute-driver` flag — that lives on the gateway.

```powershell
$env:OPENSHELL_GATEWAY = ""   # avoid an env override
.\openshell.exe gateway add http://127.0.0.1:17670 --local --name openshell-mxc
.\openshell.exe gateway select openshell-mxc
```

`http://` here registers as plaintext (matches the gateway's `--disable-tls`).

---

## Run the demo

### Fastest path: the orchestrator script

Once the one-time setup above is done and `wxc_exec_path` is set in
`mxc-gateway.toml`, the whole test is a single command from the package folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-demo.ps1 -Backend process_container
```

It validates the artifacts, checks the port is free, patches the backend +
`wxc_exec_path` into the toml, stages `mxc-demo-agent.exe` into the share, starts
the gateway, registers + selects the CLI gateway, creates the sandbox (which runs
the test app inside), collects the verdict file, prints a deterministic **DEMO
PASS / DEMO FAIL**, and stops the gateway. Exit code `0` == PASS. Useful flags:
`-Backend isolation_session|process_container` (default `isolation_session`; use
`process_container` for the default-deny proof), `-KeepRunning` to leave the
gateway up, `-Mock` for an off-box plumbing smoke (the enforcement verdict is not
asserted in mock — see the note in the script header). The manual walkthrough
below is the same flow, broken out.

### Recommended: single-run proof with the test app

With the default `mxc-gateway.toml`, the driver launches `mxc-demo-agent.exe`,
which performs **both** the positive and negative checks in one sandbox run:

```powershell
.\openshell.exe sandbox create --name demo --policy .\demo.yaml --no-tty -- exit
```

The test app:

1. writes `hello.txt` into the granted share (in-policy write → succeeds),
2. reads it back (in-policy read → succeeds),
3. attempts a write to an out-of-policy path — by default a unique per-run file
   under the operator's own `%TEMP%` (e.g. `%TEMP%\openshell-mxc-out-of-policy-<pid>.txt`;
   `run-demo.ps1` picks and passes this). Under `process_container` the AppContainer
   denies it; under `isolation_session` it would succeed and the verdict would be FAIL.

> **Why the operator's own temp, not `C:\Windows\Temp`?** The negative probe must never
> target a shared, privileged directory. Under `isolation_session` the write succeeds and
> the file is created by the ephemeral agent USER; a non-admin operator then cannot delete
> it, and it poisons every later `process_container` run. An operator-owned,
> unique-per-run path is always cleanable and never collides.

It exits `0` only when all three behave correctly (so the sandbox self-reports
`Ready`); if the out-of-policy write were ever allowed it exits non-zero and the
sandbox enters the error phase. The verdict is also written host-side:

```powershell
Get-Content C:\work\openshell-mxc-demo\hello.txt                  # → hello from mxc
Get-Content C:\work\openshell-mxc-demo\mxc-demo-agent-result.txt  # → per-check [PASS] lines + OVERALL: PASS
# The negative probe target is printed by run-demo.ps1 ("set out-of-policy target -> ...").
# For process_container it should be absent (denied write never landed).
```

The two manual flows below remain valid if you want to drive the positive and
negative proofs as separate sandbox runs (e.g. to show the error phase live);
switch `agent_command` to the commented PowerShell fallback in `mxc-gateway.toml`.

### Positive proof — in-policy write succeeds

```powershell
.\openshell.exe sandbox create --name demo-pos --policy .\demo.yaml --no-tty -- exit
```

Expected:

- CLI prints `Created sandbox: demo-pos`.
- Gateway window logs the full lifecycle:
  - `MXC provisioned sandbox=demo-pos iso_id=iso:wxc-…`
  - `MXC started sandbox=demo-pos`
  - `MXC agent exec launched sandbox=demo-pos command=powershell …`
  - `Sandbox phase changed … old_phase=Provisioning new_phase=Ready`  ← **self-reported Ready**
  - `MXC agent exec completed successfully sandbox=demo-pos`
- The CLI's post-create interactive attach **will fail** with
  `supervisor session not connected` — that's expected (interactive attach is
  deferred to a follow-up Windows skill). The create + agent run completed
  before the attach was attempted.
- **The proof:** the host file exists:

  ```powershell
  Get-Content C:\work\openshell-mxc-demo\hello.txt
  # → hello from mxc
  ```

### Negative proof — out-of-policy write is denied

> **Requires `backend = "process_container"`.** Under `isolation_session` this
> write **succeeds** (grant-only backend, no deny primitive) and the sandbox
> reaches Ready instead of erroring — that is the expected `isolation_session`
> behavior, not a denial. Set `backend = "process_container"` for this proof.

Edit `mxc-gateway.toml` so `agent_command` targets an **out-of-policy** path,
e.g.:

```toml
# Target an out-of-policy path under YOUR OWN temp (so it stays cleanable). Do NOT
# use a shared/privileged dir like C:\Windows\Temp. Pick a
# FRESH filename for each attempt (bump the suffix, e.g. -001, -002) and use the
# SAME literal path in the Test-Path proof below. A per-run-unique name keeps a
# stale file from an earlier attempt (e.g. one run under isolation_session, where
# the write succeeds) from showing up here as a false "not denied" result.
# (The automated run-demo.ps1 does this for you; this is the manual equivalent.)
agent_command = [
  "powershell",
  "-NoProfile",
  "-Command",
  "Set-Content -Path \"$env:TEMP/openshell-mxc-out-of-policy-001.txt\" -Value 'should be denied'",
]
```

Restart the gateway (Ctrl+C in Window 1, relaunch the same command). Then:

```powershell
.\openshell.exe sandbox create --name demo-neg --policy .\demo.yaml --no-tty -- exit
```

Expected:

- CLI prints `Created sandbox: demo-neg` then fails with
  `sandbox entered error phase while provisioning: ExecFailed: Agent exec exited 1`.
- Gateway window logs:
  - `MXC agent exec launched sandbox=demo-neg command=powershell …`
  - `WARN MXC agent exec exited non-zero sandbox=demo-neg exit_code=1`
  - `WARN Sandbox failed to become ready … reason=ExecFailed Agent exec exited 1`
  - A `DriverPlatformEvent` with `reason=AgentExecFailed` and message
    `agent exited with code 1; possible out-of-policy write`.
- **The proof:**

  ```powershell
  # Use the SAME filename you put in agent_command above (bump the suffix per run).
  Test-Path "$env:TEMP\openshell-mxc-out-of-policy-001.txt"
  # → False
  ```

  AppContainer denied the write; the file never appeared.

Where you see the denial (three independent surfaces, in order of obviousness):

1. The CLI's error line (above).
2. The gateway console (`AgentExecFailed` log line).
3. The OCSF JSONL log if `OPENSHELL_OCSF_LOG_PATH` is set on the gateway.

### Cleanup

```powershell
.\openshell.exe sandbox list           # confirms both sandboxes by name
.\openshell.exe sandbox delete demo-pos
.\openshell.exe sandbox delete demo-neg
```

`delete` calls `wxc-exec phase=stop` then `phase=deprovision` and removes the
session from the driver's registry. Confirm with `sandbox list`.

---

## Troubleshooting

| Symptom | Cause + fix |
|---|---|
| Gateway exits at start: `mxc compute driver is only available on Windows` | You're not on Windows. The driver is `cfg(target_os = "windows")`-gated. |
| Gateway exits: `mxc compute driver is opt-in only` | Add `OPENSHELL_COMPUTE_DRIVER=mxc` to the environment, or pass `--compute-driver mxc`. |
| `wxc-exec --probe` fails / `backend_unavailable` from the driver | `IsoSessionApp.dll` not registered or velocity key off — pre-flight item 2/4. |
| `wxc-exec` not found | `wxc_exec_path` in `mxc-gateway.toml` is wrong; fix and restart the gateway. |
| CLI: `register it first` / `gateway not found` | `openshell gateway add` step skipped, or `OPENSHELL_GATEWAY` env points at the wrong one. |
| CLI: `Unauthenticated / missing principal` on a non-create RPC | Some CLI subcommands require client auth even when the gateway runs with `--disable-tls`. Use `delete` (works) instead of `get` for verification, or stand the gateway up with mTLS for the full surface. |
| Positive proof: `hello.txt` not on host | `share_dir` / `agent_command` target path / `demo.yaml` `read_write` entry must be identical. Off-by-one slash = no file. Also check for a leaked sandbox name collision (`sandbox '<name>' already exists`): `run-demo.ps1` now uses a unique per-run name; for manual runs, `openshell.exe sandbox delete <name>` first. |
| Negative proof: the out-of-policy file exists | Are you on `backend = "process_container"`? Under `isolation_session` the write is **expected** to succeed (grant-only, no default-deny). Switch to `process_container`. If already on it, check the gateway log shows `readwritePaths` mapped from `demo.yaml` and that an AppContainer isolation tier is available. NOTE: never point the negative probe at a shared/privileged dir (e.g. `C:\Windows\Temp`) — a prior `isolation_session` run leaves an agent-owned file there that a non-admin can't delete, which then makes `process_container` falsely report "file exists". `run-demo.ps1` targets the operator's own `%TEMP%` with a unique name to avoid this. |
| `libz3.dll not found` when running the CLI | Make sure `libz3.dll` is in the same folder as `openshell.exe` (the package script puts it there). |

---

## Verification boundary — what's already proven off-box vs. what only this machine can prove

**Already green from the off-box mock harness** (no `wxc-exec`, no isolation
session needed) — these did not need this box:

- The full create → provision → start → exec → self-reported Ready lifecycle.
- The PolicyMapper seam → embedded `policy_map` module mapping
  `demo.yaml`'s `filesystem_policy.read_write` to MXC `readwritePaths`.
- Out-of-policy writes routed through a denial path (`AgentExecFailed`
  `DriverPlatformEvent`) with non-zero exec exit.
- Unrepresentable policy (network on isolation_session, process/uid) fails
  `CreateSandbox` with `invalid_argument` — never silently dropped.
- Stop/delete round-tripping through the in-memory driver registry.

**Only this machine can prove (live)** — what the demo audience watches:

- Real `wxc-exec` provisioning a real AppContainer with the policy shares.
- Real AppContainer **OS-enforced** default-deny of the out-of-policy write
  **under `process_container`** (the off-box harness simulates this; the demo box
  proves it). Note `isolation_session` does **not** deliver this — it is
  grant-only and the out-of-policy write succeeds there.
- `hello.txt` appearing on the host shared folder from inside the sandbox.

Everything else this runbook walks through is mechanical — copy the package,
run two binaries, observe the file.
