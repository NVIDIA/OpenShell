<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenShell MXC filesystem enforcement runbook

Use this runbook on a Windows 11 host with a live Microsoft MXC installation.
The proof launches a workload through OpenShell's MXC driver, writes inside a
granted directory, and verifies that Windows denies a write outside it.

This workflow uses the current MXC contract:

- Gateway TOML contains host runtime settings only.
- `wxc_exec_path` is required and must be absolute.
- `process_container` is the default and enforces filesystem grants with a
  default-deny AppContainer boundary.
- Each sandbox receives its `command` and `cwd` through
  `--driver-config-json`; gateway fields such as `agent_command`, `agent_cwd`,
  `agent_env`, and `share_dir` no longer exist.
- `isolation_session` is opt-in and rejects policies with non-empty filesystem
  grants. Do not use it for this enforcement proof.

## Required files

Place these files in one writable directory:

| File | Purpose |
|---|---|
| `openshell-gateway.exe` | Gateway with the in-process MXC driver. |
| `openshell.exe` | OpenShell CLI. |
| `libz3.dll` | Runtime dependency of the CLI package. |
| `mxc-gateway.toml` | MXC host runtime configuration. |
| `demo.yaml` | Filesystem policy granting `C:/work/openshell-mxc-demo`. |
| `mxc-demo-runbook.md` | This runbook. |

The workload is a generated `.cmd` file in the granted directory. This
runbook does not depend on a separately packaged demo agent or orchestration
script.

## Preflight

Open PowerShell in the package directory and set the path to the MXC binary:

```powershell
$wxc = "C:\mxc\wxc-exec.exe"
if (-not (Test-Path -LiteralPath $wxc -PathType Leaf)) {
  throw "wxc-exec.exe was not found at $wxc"
}
& $wxc --version
```

Resolve any `wxc-exec` failure before starting OpenShell. The OpenShell package
does not install or repair MXC.

Create the directory granted by `demo.yaml`:

```powershell
$share = "C:\work\openshell-mxc-demo"
New-Item -ItemType Directory -Path $share -Force | Out-Null
```

If you change `$share`, update the `read_write` entry in `demo.yaml` to the same
absolute path with forward slashes.

## Render the gateway configuration

Create a per-run configuration rather than editing the shipped template:

```powershell
$configPath = Join-Path $PWD "mxc-gateway.used.toml"
$config = [System.IO.File]::ReadAllText((Join-Path $PWD "mxc-gateway.toml"))
$escapedWxc = $wxc.Replace('\', '\\').Replace('"', '\"')
$config = [regex]::Replace(
  $config,
  '(?m)^\s*wxc_exec_path\s*=.*$',
  "wxc_exec_path = `"$escapedWxc`""
)
$config = [regex]::Replace(
  $config,
  '(?m)^\s*backend\s*=.*$',
  'backend = "process_container"'
)
[System.IO.File]::WriteAllText(
  $configPath,
  $config,
  (New-Object System.Text.UTF8Encoding($false))
)
```

The rendered `[openshell.drivers.mxc]` table should contain at least:

```toml
wxc_exec_path = "C:\\mxc\\wxc-exec.exe"
backend = "process_container"
```

## Start the gateway

In the first PowerShell window, isolate demo state and start the gateway:

```powershell
$demoState = Join-Path $PWD ".openshell-mxc-demo-state"
$env:XDG_CONFIG_HOME = Join-Path $demoState "config"
$env:XDG_STATE_HOME = Join-Path $demoState "state"
$env:OPENSHELL_SYSTEM_GATEWAY_DIR = Join-Path $demoState "system-config"
$env:OPENSHELL_GATEWAY_CONFIG = $configPath
$env:OPENSHELL_COMPUTE_DRIVER = "mxc"

.\openshell-gateway.exe --disable-tls --db-url sqlite::memory: `
  --port 17670 --log-level info
```

Healthy startup logs report `driver=mxc` and a listener on
`127.0.0.1:17670`. If startup rejects `wxc_exec_path`, verify that the rendered
value is absolute and points at the intended binary.

## Register the gateway

In a second PowerShell window, set the same isolated state paths and register
the endpoint:

```powershell
$demoState = Join-Path $PWD ".openshell-mxc-demo-state"
$env:XDG_CONFIG_HOME = Join-Path $demoState "config"
$env:XDG_STATE_HOME = Join-Path $demoState "state"
$env:OPENSHELL_SYSTEM_GATEWAY_DIR = Join-Path $demoState "system-config"

.\openshell.exe gateway add http://127.0.0.1:17670 --local --name openshell-mxc
.\openshell.exe gateway select openshell-mxc
```

## Positive proof: a granted write succeeds

Create the workload inside the granted directory:

```powershell
$share = "C:\work\openshell-mxc-demo"
$cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
$positiveScript = Join-Path $share "positive.cmd"
$positiveResult = Join-Path $share "hello.txt"
Remove-Item -LiteralPath $positiveResult -Force -ErrorAction SilentlyContinue

@"
@echo off
echo OpenShell MXC>"$positiveResult"
"@ | Set-Content -LiteralPath $positiveScript -Encoding Ascii

$positiveConfig = @{
  mxc = @{
    command = @($cmdExe, "/d", "/s", "/c", $positiveScript)
    cwd = $share
  }
} | ConvertTo-Json -Compress -Depth 8

.\openshell.exe sandbox create --name mxc-positive --policy .\demo.yaml `
  --driver-config-json $positiveConfig --no-tty
```

Wait for the one-shot workload to complete, then verify the host artifact:

```powershell
Start-Sleep -Seconds 3
.\openshell.exe sandbox get mxc-positive --output json
Get-Content -LiteralPath $positiveResult
```

PASS requires a `Ready`/`AgentCompleted` sandbox and `hello.txt` containing
`OpenShell MXC`.

## Negative proof: an ungranted write is denied

Choose a fresh target outside the granted directory and create another
workload script inside the granted directory:

```powershell
$deniedTarget = Join-Path ([System.IO.Path]::GetTempPath()) `
  "openshell-mxc-denied-$([Guid]::NewGuid().ToString('N')).txt"
$negativeScript = Join-Path $share "negative.cmd"

@"
@echo off
echo should-not-exist>"$deniedTarget"
"@ | Set-Content -LiteralPath $negativeScript -Encoding Ascii

$negativeConfig = @{
  mxc = @{
    command = @($cmdExe, "/d", "/s", "/c", $negativeScript)
    cwd = $share
  }
} | ConvertTo-Json -Compress -Depth 8

.\openshell.exe sandbox create --name mxc-negative --policy .\demo.yaml `
  --driver-config-json $negativeConfig --no-tty
```

Inspect the terminal state and the host path:

```powershell
Start-Sleep -Seconds 3
.\openshell.exe sandbox get mxc-negative --output json
Test-Path -LiteralPath $deniedTarget
```

PASS requires the workload to report an error caused by access denial and
`Test-Path` to return `False`. A successful write is a failed enforcement proof.

## Cleanup

Delete both sandbox records, stop the gateway with Ctrl+C, and remove the
test-owned artifacts:

```powershell
.\openshell.exe sandbox delete mxc-positive
.\openshell.exe sandbox delete mxc-negative
.\openshell.exe gateway remove openshell-mxc

Remove-Item -LiteralPath $share -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PWD ".openshell-mxc-demo-state") `
  -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PWD "mxc-gateway.used.toml") `
  -Force -ErrorAction SilentlyContinue
```

## Troubleshooting

| Symptom | Action |
|---|---|
| Gateway rejects `wxc_exec_path` | Use an absolute path and confirm the rendered TOML contains doubled backslashes. |
| Gateway reports an unknown MXC field | Start from the shipped `mxc-gateway.toml`; do not add removed workload fields to gateway configuration. |
| Sandbox says the command is missing | Ensure `--driver-config-json` contains `mxc.command` and that the executable/path values are absolute. |
| Positive write is denied | Ensure the `cwd`, scripts, and result file are under the path granted by `demo.yaml`. |
| Negative write succeeds | Confirm the gateway uses `backend = "process_container"`; stop and investigate before treating the host as qualified. |
| `isolation_session` rejects the policy | Expected: this backend does not accept non-empty OpenShell filesystem grants. Use `process_container` for this proof. |
