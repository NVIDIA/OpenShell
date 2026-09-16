# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-ws-agent-test.ps1 - WebSocket agent lifecycle test for OpenShell MXC ProcessContainer.
#
# Tests the full lifecycle of a WebSocket sandbox reached via dynamic
# `openshell forward service` bridging (the same mechanism
# run-openclaw-forward-test.ps1 exercises against a real OpenClaw gateway --
# this test uses a small built-in WS echo server instead):
#
#   1. Start openshell-gateway configured for ProcessContainer, with
#      mxc-ws-agent.exe (server mode) wrapped by openshell-supervisor-relay.exe
#      (pc_relay_spawner_path / pc_relay_target_port).
#   2. Create a sandbox using ws-agent.yaml policy.  The gateway launches
#      openshell-supervisor-relay.exe inside the AppContainer, which spawns
#      the WebSocket echo server on port 22000 once the driver's "launch"
#      handshake completes.
#   3. Wait for port 22000 to become available (server is ready).
#   4. `openshell forward service --target-port 22000` opens a fresh,
#      on-demand relay; connect a WebSocket client through it, send a
#      message, verify the echo.
#   5. Delete the sandbox.  The driver sends a "shutdown" control-channel
#      request (and kills wxc-exec as a backstop regardless) -> the spawner
#      kills the server directly -> AppContainer tears down -> port 22000
#      freed.
#   6. Verify port 22000 is freed within the drain timeout.
#
# In -Mock mode: steps 3-4 and 6 are skipped because wxc-exec is not invoked
# and the server never starts.  The test validates gateway startup, sandbox
# create, and sandbox delete only.
#
# PowerShell 5.1-compatible (no && / || / ternary operators).  ASCII only.
#
# Usage (from the directory containing openshell-gateway.exe / openshell.exe):
#
#   # Real run against a live MXC backend:
#   .\run-ws-agent-test.ps1 -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe
#
#   # Wiring-only smoke test (no wxc-exec required):
#   .\run-ws-agent-test.ps1 -Mock
#
#   # Override the agent directory (default: C:\work\openshell-mxc-ws):
#   .\run-ws-agent-test.ps1 -WxcExecPath ... -AgentDir C:\work\openshell-mxc-ws
#
# Exit code: 0 = PASS, 1 = FAIL.

[CmdletBinding()]
param(
    # Path to wxc-exec.exe.  Required for real runs; ignored in mock mode.
    [string] $WxcExecPath = "",

    # Working directory the AppContainer can read/write. mxc-ws-agent.exe is
    # expected alongside this script;
    # the script copies it here if needed.
    [string] $AgentDir = "C:\work\openshell-mxc-ws",

    # Gateway gRPC port (matches the openshell-gateway default).
    [int]    $Port        = 17670,

    # Gateway name registered with the CLI.
    [string] $GatewayName = "openshell-mxc-ws-test",

    # Port the WebSocket server binds inside the AppContainer. NOT actually
    # overridable today -- it's a compile-time const in mxc-ws-agent.rs; any
    # other value is rejected below rather than silently ignored.
    [int]    $WsPort = 22000,

    # Local host port `openshell forward service` binds for this run's
    # on-demand relay. Host clients connect here; the CLI bridges them to the
    # in-sandbox server via the driver's dynamic forward (ForwardSink::
    # open_dynamic_forward). Freely overridable -- unlike -WsPort, this one
    # actually is wired through end to end.
    [int]    $RelayPort = 22001,

    # WebSocket echo message sent during the connectivity check.
    [string] $WsMessage = "hello-ws",

    # Skip wxc-exec invocation and AppContainer enforcement; validates gateway
    # startup, sandbox create/delete lifecycle only.
    [switch] $Mock,

    # Keep the gateway running after the test (useful for manual inspection).
    [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- Results bundle -----------------------------------------------------------

$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-ws-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
$transcriptStarted = $false

# --- Helpers ------------------------------------------------------------------

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }
function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)  { Write-Host "[FAIL] $m" -ForegroundColor Red }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

# Escape backslashes for TOML basic strings.
function Esc([string]$p) { return $p.Replace('\', '\\') }

# Convert Windows path to forward-slash form (TOML values).
function Fwd([string]$p) { return $p.Replace('\', '/') }

# -WsPort is NOT actually wired through end to end: the in-sandbox server's
# port is a compile-time const (WS_PORT = 22000 in mxc-ws-agent.rs) -- the
# TOML generation below doesn't patch it. Rather than silently accept an
# override that has no effect, reject it explicitly so a caller doesn't waste
# time debugging a "port already in use" against a port this test never
# actually uses. -RelayPort has no such restriction: it's just the local
# port passed to `openshell forward service --local`, freely chosen per run.
if ($WsPort -ne 22000) {
    throw "-WsPort is not wired through to the sandboxed server (compile-time const in mxc-ws-agent.rs); only the default 22000 is supported."
}

# --- Path variables -----------------------------------------------------------

$gateway    = Join-Path $here "openshell-gateway.exe"
$cli        = Join-Path $here "openshell.exe"
$tomlSrc    = Join-Path $here "mxc-ws-gateway.toml"
$toml       = Join-Path $resultDir "mxc-ws-gateway.toml"
$policyFile = Join-Path $here "e2e-policies\ws-agent.yaml"
$policyUsed = Join-Path $resultDir "ws-agent.yaml"

$agentExeSrc = Join-Path $here "mxc-ws-agent.exe"
$agentExe    = Join-Path $AgentDir "mxc-ws-agent.exe"

# openshell-supervisor-relay.exe wraps the per-sandbox command (see mxc-ws-gateway.toml's
# pc_relay_spawner_path) so the driver has a control channel into the sandbox,
# which dynamic forwarding depends on.
$relayExeSrc = Join-Path $here "openshell-supervisor-relay.exe"
$relayExe    = Join-Path $AgentDir "openshell-supervisor-relay.exe"

$gwLog    = Join-Path $resultDir "gateway.log"
$gwErrLog = Join-Path $resultDir "gateway.err.log"
$fwdLog    = Join-Path $resultDir "forward.log"
$fwdErrLog = Join-Path $resultDir "forward.err.log"

$script:gwProc  = $null
$script:fwdProc = $null
$runId          = Get-Date -Format 'MMddHHmmss'
$sandboxName    = "mxc-ws-$runId"

# --- Gateway management -------------------------------------------------------

function Start-Gw {
    Remove-Item $gwLog, $gwErrLog -Force -ErrorAction SilentlyContinue
    $env:OPENSHELL_GATEWAY_CONFIG = $toml
    $env:OPENSHELL_DRIVERS        = "mxc"
    $env:OPENSHELL_MXC_SHARE_DIR  = $AgentDir
    $p = Start-Process -FilePath $gateway `
        -ArgumentList @("--disable-tls", "--db-url", "sqlite::memory:", "--log-level", "info", "--port", $Port) `
        -WorkingDirectory $here -PassThru -NoNewWindow `
        -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) {
            Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue |
                ForEach-Object { Info $_ }
            throw "gateway exited early (code $($p.ExitCode)). See $gwLog."
        }
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
            return $p
        }
        Start-Sleep -Milliseconds 400
    }
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    throw "gateway did not start within 30 s."
}

function Stop-Gw($p) {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700
}

# --- CLI registration ---------------------------------------------------------

function Register-Cli {
    $env:OPENSHELL_GATEWAY = ""
    $addMsg = ""
    try {
        & $cli gateway add "http://127.0.0.1:$Port" --local --name $GatewayName 2>&1 |
            ForEach-Object { $addMsg += "$_`n"; Info $_ }
    } catch {
        $addMsg = $_.Exception.Message
        Info "gateway add: $addMsg"
    }
    if ($addMsg -match 'different endpoint') {
        # Registered at a stale port; remove and re-add.
        Info "removing stale gateway registration and re-adding at port $Port"
        try { & $cli gateway remove $GatewayName 2>&1 | Out-Null } catch {}
        try {
            & $cli gateway add "http://127.0.0.1:$Port" --local --name $GatewayName 2>&1 |
                ForEach-Object { Info $_ }
        } catch { Info "gateway add retry: $($_.Exception.Message) (continuing)" }
    }
    try { & $cli gateway select $GatewayName 2>&1 | ForEach-Object { Info $_ } }
    catch { Info "gateway select: $($_.Exception.Message) (continuing)" }
}

# --- Port polling -------------------------------------------------------------

function Wait-PortOpen([int]$port, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-PortClosed([int]$port, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# --- WebSocket echo test ------------------------------------------------------
#
# Uses System.Net.WebSockets.ClientWebSocket (.NET 4.5+ / PS 5.1).
# Sends $msg over WebSocket and checks the server echoes it back unchanged.

function Test-WsEcho([string]$wsHost, [int]$port, [string]$msg) {
    $uri = [Uri]("ws://" + $wsHost + ":" + $port)
    $ws  = New-Object System.Net.WebSockets.ClientWebSocket
    $cts = New-Object System.Threading.CancellationTokenSource(10000)

    try {
        Info "connecting to $uri ..."
        $ws.ConnectAsync($uri, $cts.Token).Wait()
        if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            throw ("WebSocket did not open (state: " + $ws.State + ")")
        }
        Info "connected"

        # Send a text frame.
        $sendBytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
        $segment   = New-Object System.ArraySegment[byte] (,$sendBytes)
        $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text,
            $true, $cts.Token).Wait()
        Info "sent: $msg"

        # Receive the echo.
        $recvBuf  = New-Object byte[] 4096
        $recvSeg  = New-Object System.ArraySegment[byte] (,$recvBuf)
        $result   = $ws.ReceiveAsync($recvSeg, $cts.Token).Result
        $echo     = [System.Text.Encoding]::UTF8.GetString($recvBuf, 0, $result.Count)
        Info "received: $echo"

        $echoMatched = ($echo -eq $msg)

        # Graceful close -- best-effort.  The relay may not complete the WS
        # Close handshake, so ignore close errors when the echo already matched.
        try {
            $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,
                "test done", $cts.Token).Wait()
        } catch {}

        return $echoMatched
    } catch {
        Warn ("WebSocket test error: " + $_.Exception.GetBaseException().Message)
        return $false
    } finally {
        $cts.Dispose()
        $ws.Dispose()
    }
}

# --- Render gateway TOML ------------------------------------------------------

function Render-Toml {
    if (-not (Test-Path $tomlSrc)) {
        throw "base TOML not found at $tomlSrc"
    }
    $t = Get-Content $tomlSrc -Raw

    if (-not $Mock) {
        $t = [regex]::Replace($t, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$',
            "wxc_exec_path = `"$(Esc $WxcExecPath)`"")
    }

    $relayExeFwd = Fwd $relayExe

    $t = [regex]::Replace($t, '(?m)^\s*#?\s*pc_relay_spawner_path\s*=.*$',
        "pc_relay_spawner_path = `"$relayExeFwd`"")

    Set-Content $toml -Value $t -Encoding UTF8
}

# --- Render policy (disposable copy) ------------------------------------------

# The policy's read_write grant is the only source of filesystem access now
# (the driver never adds a workload directory automatically) -- it hardcodes
# the default AgentDir, so it needs the same -AgentDir substitution or an override loses its grant
# entirely and the wrapped server can't even read its own binary/DLLs.
function Render-Policy {
    if (-not (Test-Path $policyFile)) {
        throw "policy not found at $policyFile"
    }
    $p = Get-Content $policyFile -Raw
    $defaultAgentDirPolicy = "C:/work/openshell-mxc-ws"
    $agentDirPolicy = (Fwd $AgentDir)
    if ($agentDirPolicy -ne $defaultAgentDirPolicy) {
        $p = $p.Replace($defaultAgentDirPolicy, $agentDirPolicy)
    }
    Set-Content $policyUsed -Value $p -Encoding UTF8
}

# --- Results tracking ---------------------------------------------------------

$checks       = New-Object System.Collections.ArrayList
$harnessError = $null

function Record([string]$name, [bool]$pass, [string]$detail) {
    $resultStr = if ($pass) { "PASS" } else { "FAIL" }
    $r = [pscustomobject]@{ Check = $name; Result = $resultStr; Detail = $detail }
    [void]$checks.Add($r)
    if ($pass) { Ok ($name + ": " + $detail) } else { Bad ($name + ": " + $detail) }
}

# =============================================================================
# MAIN
# =============================================================================

try {
    Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null
    $transcriptStarted = $true

    # --- Pre-flight -----------------------------------------------------------

    Step "Pre-flight"

    if ($Mock) {
        Info "mock mode: OPENSHELL_MXC_MOCK_WXC=1 -- wxc-exec not invoked, WS connectivity skipped"
        $env:OPENSHELL_MXC_MOCK_WXC = "1"
    } else {
        Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($WxcExecPath) -or -not (Test-Path $WxcExecPath)) {
            throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath or use -Mock."
        }
        Ok "wxc-exec: $WxcExecPath"

        # A real run exercises process_container with egress_proxy = true
        # (mxc-ws-gateway.toml). MXC schema 0.8.0-alpha's network_json()
        # (mxc.rs) now emits a direct egress.allow rule for 127.0.0.0/8
        # instead of runtimeConfig.networkProxy when a proxy is configured,
        # so the driver no longer calls the elevation-only
        # NetworkIsolationSetAppContainerConfig -- process_container +
        # egress_proxy selects the BaseContainer/PSEC tier and runs
        # non-elevated. Elevation is therefore no longer required here; keep
        # logging the elevation state for diagnostics only.
        $wid   = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp    = New-Object Security.Principal.WindowsPrincipal($wid)
        $admin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Info "elevated=$admin (not required for this build)"
    }

    foreach ($f in @($gateway, $cli, $tomlSrc, $policyFile)) {
        if (-not (Test-Path $f)) {
            throw "Missing artifact: $f -- Build first or run from a release package folder."
        }
    }
    Ok "gateway, CLI, TOML template, policy file: present"

    # Prepare the agent directory and copy the built binaries.
    New-Item -ItemType Directory -Force $AgentDir | Out-Null
    # Remove stale files from previous runs.
    Remove-Item (Join-Path $AgentDir "openshell-shutdown.signal") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $AgentDir "appcontainer-sid.txt")      -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $AgentDir "outbound-probe.txt")        -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $AgentDir "outbound-probe-addr.txt")   -Force -ErrorAction SilentlyContinue
    if (Test-Path $agentExeSrc) {
        try {
            Copy-Item $agentExeSrc $agentExe -Force
            Ok "mxc-ws-agent.exe copied from release build"
        } catch {
            # File is locked by a stale process from a previous run.
            # If an existing copy is present it is safe to proceed - the lock
            # just means an AppContainer is still holding the old image.
            if (Test-Path $agentExe) {
                Warn ("Could not overwrite mxc-ws-agent.exe (file in use): " + $_.Exception.Message)
                Warn "Proceeding with the existing copy -- it may be an older build."
            } else {
                throw
            }
        }
    } elseif (-not (Test-Path $agentExe)) {
        throw ("mxc-ws-agent.exe not found at " + $agentExeSrc + " or " + $agentExe + ". " +
               "Run from the package folder (mxc-ws-agent.exe should sit alongside this script), " +
               "or build with: cargo build --release --target x86_64-pc-windows-msvc -p openshell-driver-mxc --example mxc-ws-agent")
    } else {
        Info "mxc-ws-agent.exe already in $AgentDir (using existing)"
    }

    if (Test-Path $relayExeSrc) {
        try {
            Copy-Item $relayExeSrc $relayExe -Force
            Ok "openshell-supervisor-relay.exe copied from release build"
        } catch {
            if (Test-Path $relayExe) {
                Warn ("Could not overwrite openshell-supervisor-relay.exe (file in use): " + $_.Exception.Message)
                Warn "Proceeding with the existing copy -- it may be an older build."
            } else {
                throw
            }
        }
    } elseif (-not (Test-Path $relayExe)) {
        throw ("openshell-supervisor-relay.exe not found at " + $relayExeSrc + " or " + $relayExe + ". " +
               "Run from the package folder (it should sit alongside this script), " +
               "or build with: cargo build --release --target x86_64-pc-windows-msvc -p openshell-supervisor-relay")
    } else {
        Info "openshell-supervisor-relay.exe already in $AgentDir (using existing)"
    }

    # --- Port availability ----------------------------------------------------

    Step "Check ports"
    $busyGw = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($busyGw) {
        throw "gateway port $Port already in use (pid $($busyGw.OwningProcess)). Stop stale process first."
    }
    Ok "gateway port $Port is free"

    $busyWs = Get-NetTCPConnection -State Listen -LocalPort $WsPort -ErrorAction SilentlyContinue
    if ($busyWs) {
        throw "WebSocket port $WsPort already in use (pid $($busyWs.OwningProcess)). Free it before running this test."
    }
    Ok "WebSocket port $WsPort is free"

    $busyRelay = Get-NetTCPConnection -State Listen -LocalPort $RelayPort -ErrorAction SilentlyContinue
    if ($busyRelay) {
        throw "relay port $RelayPort already in use (pid $($busyRelay.OwningProcess)). Free it before running this test."
    }
    Ok "relay port $RelayPort is free"

    # --- Render TOML + start gateway ------------------------------------------

    Step "Render gateway TOML"
    Render-Toml
    Render-Policy
    Copy-Item $toml (Join-Path $resultDir "mxc-ws-gateway.rendered.toml") -Force -ErrorAction SilentlyContinue
    Info "rendered TOML: $toml"
    Info "policy: $policyUsed"

    Step "Start gateway (port $Port)"
    $script:gwProc = Start-Gw
    Info "gateway pid $($script:gwProc.Id)"
    Record "gateway-start" $true "pid $($script:gwProc.Id), port $Port"

    # --- Register CLI ---------------------------------------------------------

    Step "Register CLI"
    Register-Cli
    Ok "gateway '$GatewayName' registered"

    # --- Create sandbox -------------------------------------------------------

    Step "Create sandbox '$sandboxName'"
    $createOut = $null; $createExitCode = 0
    $driverConfigJson = @{
        mxc = @{
            command = @((Fwd $agentExe), "server")
            cwd = (Fwd $AgentDir)
        }
    } | ConvertTo-Json -Compress -Depth 4
    try {
        # MXC exec-in-driver has no SSH server, so any `sandbox create` invocation
        # that attempts SSH will fail with connection-refused and exit non-zero.
        # Use the same pattern as run-mxc-e2e.ps1: pass --no-tty with a no-op
        # command so the CLI fires the SSH attempt, fails quickly (connection
        # refused), and returns.  Do NOT gate on exit code here.
        $createOut = & $cli sandbox create `
            --name $sandboxName `
            --policy $policyUsed `
            --driver-config-json $driverConfigJson `
            --no-tty `
            -- cmd.exe /c exit 0 `
            2>&1
        $createExitCode = $LASTEXITCODE
    } catch {
        $createOut = $_.Exception.Message; $createExitCode = 1
    }
    $createStr = ($createOut -join "`n")
    Info "create exit: $createExitCode (non-zero expected for MXC -- no SSH server)"

    # Verify the sandbox actually exists by fetching it.
    Start-Sleep -Milliseconds 500
    $getOut = $null; $getExitCode = 0
    try {
        $getOut = & $cli sandbox get $sandboxName 2>&1
        $getExitCode = $LASTEXITCODE
    } catch {
        $getOut = $_.Exception.Message; $getExitCode = 1
    }
    $getStr = ($getOut -join "`n")
    # `sandbox get`'s text output prints "Phase: <name>" (see run.rs);
    # require Ready, not just presence -- a sandbox that exists but is stuck
    # Provisioning/Error is not actually usable for the WebSocket check below.
    $createOk = ($getExitCode -eq 0) -and ($getStr -notmatch 'not found|does not exist') -and ($getStr -match '(?m)^\s*Phase:\s*Ready\s*$')
    Record "sandbox-create" $createOk "sandbox $sandboxName $(if ($createOk) {'exists and is Ready'} else {'not found or not Ready after create'})"

    if (-not $createOk) {
        Info "create output: $createStr"
        Info "get output:    $getStr"
        throw "sandbox create failed: sandbox does not exist or is not Ready after create"
    }

    # --- WebSocket connectivity (real mode only) ------------------------------

    if (-not $Mock) {

        Step "Wait for WebSocket server on port $WsPort"
        $serverUp = Wait-PortOpen -port $WsPort -seconds 30
        if ($serverUp) {
            Record "server-port-open" $true "port $WsPort is listening"
        } else {
            $gwText = (Get-Content $gwLog, $gwErrLog -Raw -ErrorAction SilentlyContinue) -join "`n"
            $detail = "port $WsPort did NOT open within 30 s"
            if ($gwText -match 'CreateProcessW failed') {
                $detail = $detail + " (gateway log: agent launch failure)"
            }
            Record "server-port-open" $false $detail
        }

        # Cross-check server-port-open against openshell-supervisor-relay's own
        # confirmation, from inside the sandbox: it detects target-port
        # readiness itself (wait_for_port_ready, gated by the "launch"
        # handshake) and logs it, forwarded into the gateway log the same way
        # as every other wxc-exec stdout/stderr line. No share_dir file
        # needed -- this is the same information the marker file used to
        # carry, just sourced from the spawner's own diagnostic instead.
        if ($serverUp) {
            Step "Verify spawner's own port-ready confirmation (gateway log)"
            # The spawner's own polling (wait_for_port_ready, 300ms interval)
            # runs independently of this script's Wait-PortOpen above -- its
            # log line can land a couple of seconds after the raw TCP connect
            # already succeeded (observed up to ~2.3s). Poll for it rather
            # than checking once immediately, or this races and fails spuriously.
            $readyPattern = "port $WsPort ready after"
            $readyDeadline = (Get-Date).AddSeconds(15)
            $readyOk = $false
            while ((Get-Date) -lt $readyDeadline -and -not $readyOk) {
                $readyOk = (Test-Path $gwLog -PathType Leaf) -and (Select-String -Path $gwLog -Pattern $readyPattern -Quiet -ErrorAction SilentlyContinue)
                if (-not $readyOk) {
                    $readyOk = (Test-Path $gwErrLog -PathType Leaf) -and (Select-String -Path $gwErrLog -Pattern $readyPattern -Quiet -ErrorAction SilentlyContinue)
                }
                if (-not $readyOk) { Start-Sleep -Milliseconds 300 }
            }
            if ($readyOk) {
                Record "ws-server-marker" $true "spawner logged '$readyPattern' in the gateway log"
            } else {
                Record "ws-server-marker" $false "spawner's port-ready log line not found in gateway.log/gateway.err.log within 15 s"
            }
        } else {
            Warn "skipping ws-server-marker: server did not start"
        }

        # `openshell forward service` opens a fresh, on-demand relay for this
        # one call, bridging $WsPort (inside the sandbox) to $RelayPort (on
        # this host). No port needs to be pre-declared anywhere except
        # pc_relay_target_port's own startup liveness check. Mirrors
        # run-openclaw-forward-test.ps1's step 10.
        if ($serverUp) {
            Step "openshell forward service --target-port $WsPort --local $RelayPort"
            $script:fwdProc = Start-Process -FilePath $cli `
                -ArgumentList @("forward", "service", "--target-port", "$WsPort", "--local", "$RelayPort", $sandboxName) `
                -WorkingDirectory $here -PassThru -NoNewWindow `
                -RedirectStandardOutput $fwdLog -RedirectStandardError $fwdErrLog
            Info "forward pid $($script:fwdProc.Id)"
            $fwdDeadline = (Get-Date).AddSeconds(20); $fwdUp = $false
            while ((Get-Date) -lt $fwdDeadline) {
                if ($script:fwdProc.HasExited) { break }
                if ((Test-Path $fwdLog) -and (Select-String -Path $fwdLog -Pattern 'Forwarding' -Quiet -ErrorAction SilentlyContinue)) { $fwdUp = $true; break }
                if ((Test-Path $fwdErrLog) -and (Select-String -Path $fwdErrLog -Pattern 'Forwarding' -Quiet -ErrorAction SilentlyContinue)) { $fwdUp = $true; break }
                Start-Sleep -Milliseconds 500
            }

            if ($fwdUp) {
                Ok "forward active: 127.0.0.1:$RelayPort -> sandbox:$WsPort"

                Step "WebSocket echo test via forwarded port (ws://127.0.0.1:$RelayPort)"
                $echoOk = Test-WsEcho -wsHost "127.0.0.1" -port $RelayPort -msg $WsMessage
                if ($echoOk) {
                    Record "ws-echo" $true ("'" + $WsMessage + "' echoed via forwarded port $RelayPort")
                } else {
                    Record "ws-echo" $false "echo failed via forwarded port $RelayPort -- see transcript"
                }
            } else {
                $exitDetail = if ($script:fwdProc.HasExited) { " (forward process exited early, code $($script:fwdProc.ExitCode))" } else { "" }
                Record "ws-echo" $false "forward did not report 'Forwarding ...' within 20 s$exitDetail -- see forward.log/forward.err.log"
            }
        } else {
            Warn "skipping ws-echo: server did not start"
        }

    } else {
        Info "[mock] skipping server-port-open and ws-echo"
    }

    # Stop the forward before deleting the sandbox it points at.
    if ($script:fwdProc -and -not $script:fwdProc.HasExited) {
        try { Stop-Process -Id $script:fwdProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }

    # --- Delete sandbox -------------------------------------------------------

    Step "Delete sandbox '$sandboxName'"
    $deleteOut = $null; $deleteExitCode = 0
    try {
        $deleteOut = & $cli sandbox delete $sandboxName 2>&1
        $deleteExitCode = $LASTEXITCODE
    } catch {
        $deleteOut = $_.Exception.Message; $deleteExitCode = 1
    }
    $deleteStr = ($deleteOut -join "`n")
    Info "delete exit: $deleteExitCode"
    if ($deleteExitCode -ne 0) { Info "output: $deleteStr" }
    Record "sandbox-delete" ($deleteExitCode -eq 0) "exit $deleteExitCode"

    # --- Port freed (real mode only) ------------------------------------------

    if (-not $Mock) {
        Step "Verify port $WsPort is released after delete"
        # The driver sends a "shutdown" control-channel request (openshell-
        # supervisor-relay kills the server directly) and kills wxc-exec as a
        # backstop regardless. Allow 30 s for that plus the OS to release the
        # port.
        $portClosed = Wait-PortClosed -port $WsPort -seconds 30
        if ($portClosed) {
            Record "port-freed" $true "port $WsPort released within 30 s"
        } else {
            Record "port-freed" $false "port $WsPort still bound after 30 s"
        }
    } else {
        Info "[mock] skipping port-freed check"
    }

} catch {
    $harnessError = $_.Exception.Message
    Bad "harness error: $harnessError"
} finally {
    # --- Teardown -------------------------------------------------------------

    # Best-effort forward/sandbox cleanup in case the test failed mid-run.
    if ($script:fwdProc -and -not $script:fwdProc.HasExited) {
        try { Stop-Process -Id $script:fwdProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { & $cli sandbox delete $sandboxName 2>&1 | Out-Null } catch {}

    if (-not $KeepRunning) {
        Stop-Gw $script:gwProc
        $script:gwProc = $null
    } elseif ($script:gwProc) {
        Info "gateway pid $($script:gwProc.Id) left running (-KeepRunning)"
    }

    # --- Summary --------------------------------------------------------------

    Step "Summary"
    $checks | Format-Table -AutoSize

    $failCount = @($checks | Where-Object { $_.Result -eq "FAIL" }).Count
    $passCount = @($checks | Where-Object { $_.Result -eq "PASS" }).Count
    Write-Host "PASS=$passCount  FAIL=$failCount"

    $verdict    = if ($harnessError -or $failCount -gt 0) { "FAIL" } else { "PASS" }
    $checkLines = ($checks | ForEach-Object { "  " + $_.Result + "  " + $_.Check + ": " + $_.Detail }) -join "`n"
    $modeStr    = if ($Mock) { "MOCK (no wxc-exec, no WS connectivity)" } else { "REAL" }
    $wxcStr     = if ($Mock) { "(mock)" } else { $WxcExecPath }
    $errStr     = if ($harnessError) { "harness_error: $harnessError" } else { "" }

    $summary = "OpenShell MXC WebSocket agent test`n" +
               "====================================`n" +
               "timestamp   : $stamp`n" +
               "machine     : $env:COMPUTERNAME`n" +
               "verdict     : $verdict`n" +
               "mode        : $modeStr`n" +
               "gateway     : $gateway (port $Port)`n" +
               "agent_dir   : $AgentDir`n" +
               "agent_exe   : $agentExe`n" +
               "relay_exe   : $relayExe`n" +
               "policy      : $policyUsed`n" +
               "sandbox     : $sandboxName`n" +
               "ws_port     : $WsPort`n" +
               "relay_port  : $RelayPort (on this host)`n" +
               "ws_message  : $WsMessage`n" +
               "wxc_exec    : $wxcStr`n" +
               "totals      : PASS=$passCount  FAIL=$failCount`n" +
               "$errStr`n" +
               "`nChecks:`n$checkLines`n" +
               "`nFiles in this bundle ($resultDir):`n" +
               "  transcript.txt                  full console transcript`n" +
               "  gateway.log / gateway.err.log   gateway stdout / stderr`n" +
               "  forward.log / forward.err.log   'openshell forward service' stdout / stderr`n" +
               "  mxc-ws-gateway.rendered.toml    exact gateway config used`n" +
               "  ws-agent.yaml                   sandbox policy used`n" +
               "`nWhat PASS means:`n" +
               "  gateway-start     gateway bound port $Port within 30 s`n" +
               "  sandbox-create    sandbox reached Ready after create (CLI exit may be non-zero on MXC without SSH)`n" +
               "  server-port-open   WS server bound port $WsPort within 30 s`n" +
               "  ws-server-marker   spawner logged its own port-ready confirmation in the gateway log`n" +
               "  ws-echo            '$WsMessage' echoed via a dynamic 'openshell forward service' relay at 127.0.0.1:$RelayPort`n" +
               "                     (fresh, on-demand relay for this one call -- no static bridge, nothing pre-declared)`n" +
               "  sandbox-delete     CLI returned exit 0 for sandbox delete`n" +
               "  port-freed         port $WsPort released within 30 s of sandbox delete`n"

    Set-Content (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
    $color = if ($verdict -eq "PASS") { "Green" } else { "Red" }
    Write-Host $summary -ForegroundColor $color

    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }

    # Zip the bundle.
    try {
        $zip = Join-Path $here "results-ws-$stamp.zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
        Write-Host "`nResults bundle: $zip" -ForegroundColor Yellow
    } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($harnessError -or (@($checks | Where-Object { $_.Result -eq "FAIL" }).Count -gt 0)) {
    Write-Host "`nTEST FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nTEST PASSED" -ForegroundColor Green
    exit 0
}
