# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-mxc-e2e.ps1 - MXC e2e scenario runner.
#
# Runs a table of policy scenarios against the OpenShell MXC driver, emits
# per-scenario PASS/FAIL/SKIP(reason), prints a summary table, and exits non-zero
# unless every selected scenario passes against real MXC.
#
# Every run collects its logs beneath target/windows-e2e-results and
# zips it (mirrors the sibling run-*.ps1 scripts). The bundle contains the console
# transcript, the per-scenario gateway stdout/stderr, the exact TOML rendered for
# each scenario, the policy fixture used, and a summary.txt with the verdict table.
#
# The gateway restarts per scenario to keep logs and the in-memory database
# isolated. Workload command/cwd are supplied per sandbox through
# --driver-config-json; they are never patched into gateway configuration.
#
# Scoring:
#   Positive scenarios require successful creation and a workload artifact.
#   Deny scenarios require absent denied writes plus execution evidence.
#   A CONTROL write proves the agent ran when the policy grants a writable path;
#   an empty policy instead requires explicit driver-launch evidence.
#
# PowerShell 5.1-compatible (no && / || / ternary operators). ASCII only.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mxc-e2e.ps1 -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe
#   .\run-mxc-e2e.ps1 -Scenario fs-rw                        # single scenario
#
# Scenarios & expected verdicts:
#   fs-rw            - in-policy write to DemoDir succeeds.
#   fs-readonly      - write to read-only dir is denied; control write succeeds.
#   fs-default-deny  - ungranted write is denied after the agent launches.
#                      processcontainer only.
#   network-policy   - supervisor-owned network policy permits admission.
#   forwarding       - two TCP request/reply exchanges through OpenShell ingress.
#   service-forwarding - named HTTP service routing and endpoint deletion.

[CmdletBinding()]
param(
    [string] $DemoDir,
    [string] $BinaryDir,
    [string] $WxcExecPath = "C:\mxc-kit\bin\wxc-exec.exe",
    [ValidateSet("isolation_session", "process_container")]
    [string] $Backend     = "process_container",
    [string] $Scenario,
    [int]    $Port        = 17670,
    [string] $GatewayName = "openshell-mxc-e2e",
    [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- Results bundle -----------------------------------------------------------
# Collect every log + the exact rendered config per scenario into a timestamped
# results\ folder, then zip it (mirrors the sibling run-*.ps1 scripts). Created up
# front so the transcript (started inside the guarded region below) captures the
# whole run, including pre-flight failures.
$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $here "../../.."))
$resultsRoot = Join-Path $repoRoot "target/windows-e2e-results"
$resultDir = Join-Path $resultsRoot "results-e2e-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
if (-not $DemoDir) { $DemoDir = Join-Path $resultDir "work" }
if (-not $BinaryDir) {
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repoRoot "target" }
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $target = if ($arch -eq "Arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    $BinaryDir = Join-Path $targetRoot "$target/release"
}
$savedEnv = @{}
$processEnvironment = [Environment]::GetEnvironmentVariables("Process")
foreach ($name in @("OPENSHELL_MXC_MOCK_WXC", "OPENSHELL_WXC_EXEC_PATH", "OPENSHELL_COMPUTE_DRIVER", "OPENSHELL_MXC_SHARE_DIR")) {
    $exists = $processEnvironment.Contains($name)
    $savedEnv[$name] = [pscustomobject]@{
        Exists = $exists
        Value = if ($exists) { [string] $processEnvironment[$name] } else { $null }
    }
}
$secretDir = Join-Path $resultsRoot "keys-$stamp-$([guid]::NewGuid().ToString('N'))"
$transcriptStarted = $false

$cliStateRoot = $null
$cliEnvironmentSnapshot = @{}
$cliEnvironmentNames = @(
    "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
    "OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE",
    "OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_GATEWAY_NAME"
)

function Set-ProcessEnvironmentVariableExact {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [bool] $Exists,
        [AllowNull()]
        [string] $Value
    )

    if (-not $Exists) {
        Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
        return
    }

    if ($Value.Length -eq 0) {
        # Windows PowerShell 5.1 maps an empty value passed through
        # Environment.SetEnvironmentVariable to deletion. Call Win32 directly
        # so an inherited empty entry remains distinguishable from absence.
        if (-not ("OpenShellMxcProcessEnvironmentNative" -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class OpenShellMxcProcessEnvironmentNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetEnvironmentVariable(string name, string value);
}
'@
        }
        if (-not [OpenShellMxcProcessEnvironmentNative]::SetEnvironmentVariable($Name, [string]::Empty)) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "failed to restore empty process environment variable '$Name' (Win32 error $errorCode)"
        }
        return
    }

    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
}

function Enter-IsolatedCliEnvironment {
    $processEnvironment = [Environment]::GetEnvironmentVariables("Process")
    foreach ($name in $cliEnvironmentNames) {
        $exists = $processEnvironment.Contains($name)
        $script:cliEnvironmentSnapshot[$name] = [pscustomobject]@{
            Exists = $exists
            Value = if ($exists) { [string] $processEnvironment[$name] } else { $null }
        }
    }
    $script:cliStateRoot = Join-Path ([IO.Path]::GetTempPath()) "openshell-mxc-e2e-cli-$PID-$([Guid]::NewGuid().ToString('N'))"
    $isolatedPaths = @{
        APPDATA = Join-Path $script:cliStateRoot "appdata"
        LOCALAPPDATA = Join-Path $script:cliStateRoot "localappdata"
        XDG_CONFIG_HOME = Join-Path $script:cliStateRoot "xdg-config"
        XDG_STATE_HOME = Join-Path $script:cliStateRoot "xdg-state"
        XDG_DATA_HOME = Join-Path $script:cliStateRoot "xdg-data"
    }
    try {
        New-Item -ItemType Directory -Force -Path @($isolatedPaths.Values) | Out-Null
        foreach ($entry in $isolatedPaths.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
        }
        foreach ($name in $cliEnvironmentNames | Where-Object { -not $isolatedPaths.ContainsKey($_) }) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    } catch {
        Exit-IsolatedCliEnvironment
        throw
    }
}

function Exit-IsolatedCliEnvironment {
    foreach ($name in $cliEnvironmentNames) {
        if (-not $script:cliEnvironmentSnapshot.ContainsKey($name)) { continue }
        $snapshot = $script:cliEnvironmentSnapshot[$name]
        Set-ProcessEnvironmentVariableExact -Name $name -Exists $snapshot.Exists -Value $snapshot.Value
    }
    if ($script:cliStateRoot -and (Test-Path -LiteralPath $script:cliStateRoot)) {
        if ($KeepRunning -and $gw -and -not $gw.HasExited) {
            Write-Host "Retaining isolated CLI/runtime state for live gateway: $script:cliStateRoot"
            return
        }
        # Resolve the generated target before recursive cleanup; never remove an
        # arbitrary caller path or the temporary directory itself.
        $cleanupPath = [IO.Path]::GetFullPath($script:cliStateRoot)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $cleanupPath.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path $cleanupPath -Leaf) -notmatch '^openshell-mxc-(e2e|ocsf)-cli-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing unsafe CLI state cleanup: $cleanupPath"
        }
        Remove-Item -LiteralPath $cleanupPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Step([string]$m)  { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m)  { Write-Host "    $m" }
function Ok([string]$m)    { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)   { Write-Host "[FAIL] $m" -ForegroundColor Red }
function Skip([string]$m)  { Write-Host "[SKIP] $m" -ForegroundColor Yellow }
function Warn([string]$m)  { Write-Host "[WARN] $m" -ForegroundColor Yellow }

# Double backslashes so a Windows path is a valid TOML/JSON basic-string element.
function Esc([string]$p) { return $p.Replace('\', '\\') }

# Build one CreateProcess-compatible command-line argument. Windows PowerShell
# 5.1 can split JSON values at embedded spaces when invoking native commands
# through the call operator, even when PowerShell holds the JSON as one string.
function Quote-NativeArgument([string]$value) {
    if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }

    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($ch in $value.ToCharArray()) {
        if ($ch -eq '\') {
            $backslashes++
            continue
        }
        if ($ch -eq '"') {
            [void]$quoted.Append(('\' * (2 * $backslashes + 1)))
            [void]$quoted.Append('"')
        } else {
            if ($backslashes -gt 0) { [void]$quoted.Append(('\' * $backslashes)) }
            [void]$quoted.Append($ch)
        }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$quoted.Append(('\' * (2 * $backslashes))) }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-NativeCaptured([string]$filePath, [string[]]$argumentList, [int]$timeoutSeconds = 0) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $filePath
    $startInfo.Arguments = (($argumentList | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "failed to start $filePath" }
    } catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)Application Control policy has blocked this file') {
            $sha256 = try { (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash } catch { "unavailable" }
            $signature = try { (Get-AuthenticodeSignature -LiteralPath $filePath).Status } catch { "unavailable" }
            throw "Application Control blocked CLI launch '$filePath' (SHA256=$sha256; Authenticode=$signature). Review CodeIntegrity/Operational event 3077 to identify the blocking policy, then deploy or allow an approved binary. Original error: $message"
        }
        throw
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($timeoutSeconds -gt 0 -and -not $process.WaitForExit($timeoutSeconds * 1000)) {
        $process.Kill()
    }
    $process.WaitForExit()

    return @{
        ExitCode = $process.ExitCode
        Output = @($stdout.Result, $stderr.Result) | Where-Object { $_ }
    }
}

# --- Path variables -----------------------------------------------------------

$gateway   = Join-Path $BinaryDir "openshell-gateway.exe"
$cli       = Join-Path $BinaryDir "openshell.exe"
$tomlTemplate = Join-Path $here "mxc-gateway.toml"
$toml      = Join-Path $resultDir "mxc-gateway.toml"
$policyDir = Join-Path $here "e2e-policies"

$cmdExe     = "C:\Windows\System32\cmd.exe"
$demoDirFwd = $DemoDir.Replace('\', '/')
$defaultDemoDir = "C:\work\openshell-mxc-e2e"
$roSrc      = "$DemoDir-ro-src"      # matches e2e-policies/fs-readonly.yaml read_only path
$denyProbe  = "$DemoDir-deny-probe"  # ungranted, NOT the share: used to prove default-deny

$script:registered = $false

# Pristine TOML captured once inside the try (below); every scenario renders a
# fresh copy from it. Per-scenario gateway logs are assigned inside the loop so
# each scenario's stdout/stderr lands in its own file under $resultDir.
$tomlBase = $null
$gwLog    = $null
$gwErrLog = $null

# --- Helpers ------------------------------------------------------------------

# Render host-runtime settings from the pristine base. Sandbox workload
# settings are create-time driver config, not gateway-wide TOML.
function Render-Toml {
    $t = $tomlBase
    $t = [regex]::Replace($t, '(?m)^\s*#?\s*backend\s*=.*$', "backend = `"$Backend`"")
    $wxcLine = "wxc_exec_path = `"$(Esc $WxcExecPath)`""
    $t = [regex]::Replace($t, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$', $wxcLine)
    $t += @"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = '$(Join-Path $secretDir 'signing.pem')'
public_key_path = '$(Join-Path $secretDir 'public.pem')'
kid_path = '$(Join-Path $secretDir 'kid')'
gateway_id = 'mxc-e2e'
"@
    Set-Content $toml -Value $t -Encoding UTF8
}

function Test-PortListening {
    return @([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object { $_.Port -eq $Port }).Count -gt 0
}

function Start-Gw {
    Remove-Item $gwLog, $gwErrLog -Force -ErrorAction SilentlyContinue
    # Ephemeral in-memory DB: this is a test harness, so it must NOT write sandbox
    # records to the persistent default store (%LOCALAPPDATA%\openshell\gateway\
    # openshell.db). Without this, sandbox names persist across gateway restarts
    # and across runs, colliding on `create` ("already exists") and leaving orphan
    # records behind. In-memory means every gateway starts clean and leaves nothing.
    # Config path goes through the env var (clap: OPENSHELL_GATEWAY_CONFIG), NOT a
    # --config token: Start-Process -ArgumentList does not quote array elements, so a
    # config path containing a space gets split and the gateway's arg parser rejects it.
    $env:OPENSHELL_GATEWAY_CONFIG = $toml
    $p = Start-Process -FilePath $gateway `
        -ArgumentList @("--disable-tls", "--db-url", "sqlite::memory:", "--port", $Port, "--log-level", "info") `
        -WorkingDirectory $here -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) {
            Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
            throw "gateway exited early (code $($p.ExitCode)). See $gwLog."
        }
        if (Test-PortListening) {
            return $p
        }
        Start-Sleep -Milliseconds 400
    }
    # Timed out but the process is still alive (never bound $Port). $gw is not yet
    # assigned in the caller, so the finally block can't reap it - kill it here to
    # avoid leaving an orphan gateway holding the port for the next run.
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    throw "gateway did not start within 30 s."
}

function Stop-Gw($p) {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700   # let the listen socket release before the next start
}

function Register-Cli {
    if ($script:registered) { return }

    $addResult = Invoke-NativeCaptured $cli @(
        "gateway", "add", "http://127.0.0.1:$Port", "--local", "--name", $GatewayName
    )
    $addText = ($addResult.Output -join "`n")
    if ($addText) { $addResult.Output | ForEach-Object { Info $_ } }
    if ($addResult.ExitCode -ne 0) {
        throw "gateway add failed (exit $($addResult.ExitCode)): $addText"
    }

    $selectResult = Invoke-NativeCaptured $cli @("gateway", "select", $GatewayName)
    $selectText = ($selectResult.Output -join "`n")
    if ($selectText) { $selectResult.Output | ForEach-Object { Info $_ } }
    if ($selectResult.ExitCode -ne 0) {
        throw "gateway select failed (exit $($selectResult.ExitCode)): $selectText"
    }

    $script:registered = $true
}

function Wait-File([string]$path, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $path)) {
        Start-Sleep -Milliseconds 400
    }
    return (Test-Path $path)
}

# Exercise the public gRPC forward path, never dial the workload port directly.
# The nonce identifies this workload, not an unrelated host-loopback listener.
function Test-Forwarding([string]$sandboxName, [string]$readyFile, [string]$nonce) {
    if (-not (Wait-File $readyFile 30)) { throw "MXC forwarding listener did not report readiness" }
    $targetPort = [int](Get-Content -LiteralPath $readyFile -Raw).Trim()
    if ($targetPort -lt 1 -or $targetPort -gt 65535) { throw "Invalid workload listener port" }
    $outLog = Join-Path $resultDir "forward.stdout.log"
    $errLog = Join-Path $resultDir "forward.stderr.log"
    $arguments = @("forward", "service", $sandboxName, "--target-port", "$targetPort", "--local", "127.0.0.1:0")
    $forwarder = $null
    try {
        $forwarder = Start-Process -FilePath $cli -WindowStyle Hidden -PassThru `
            -ArgumentList (($arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' ') `
            -RedirectStandardOutput $outLog -RedirectStandardError $errLog
        $deadline = (Get-Date).AddSeconds(30)
        $localPort = 0
        while ((Get-Date) -lt $deadline) {
            if ($forwarder.HasExited) { throw "CLI forwarder exited early (code $($forwarder.ExitCode)); see $errLog" }
            $text = (Get-Content -LiteralPath $errLog -Raw -ErrorAction SilentlyContinue)
            if ($text -match 'Forwarding 127\.0\.0\.1:(\d+) ->') {
                $localPort = [int]$Matches[1]
                break
            }
            Start-Sleep -Milliseconds 200
        }
        if ($localPort -eq 0) { throw "CLI forwarder did not bind within 30 seconds" }
        for ($exchange = 1; $exchange -le 2; $exchange++) {
            $socket = New-Object System.Net.Sockets.TcpClient
            $reader = $null
            try {
                $connect = $socket.BeginConnect('127.0.0.1', $localPort, $null, $null)
                try {
                    if (-not $connect.AsyncWaitHandle.WaitOne(5000)) { throw "Forward client connection timed out" }
                    $socket.EndConnect($connect)
                } finally { $connect.AsyncWaitHandle.Close() }
                $socket.NoDelay = $true
                $stream = $socket.GetStream()
                $stream.ReadTimeout = 10000
                $stream.WriteTimeout = 10000
                $request = "request-$exchange-$([guid]::NewGuid().ToString('N'))"
                $bytes = [Text.Encoding]::ASCII.GetBytes("$request`n")
                $stream.Write($bytes, 0, $bytes.Length)
                $socket.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
                $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
                $reply = $reader.ReadLine()
                if ($reply -ne "$nonce`:$request") { throw "Forwarded exchange $exchange returned an unexpected response: '$reply'" }
                Info "forwarded exchange ${exchange}: exact workload response verified"
            } finally {
                if ($reader) { $reader.Dispose() }
                $socket.Close()
            }
        }
    } finally {
        if ($forwarder) {
            if (-not $forwarder.HasExited) { Stop-Process -Id $forwarder.Id -Force -ErrorAction SilentlyContinue }
            $forwarder.Dispose()
        }
    }
}

# Connect to the gateway only, setting the exposed service URL's Host header.
# This avoids DNS requirements and cannot accidentally dial the workload directly.
function Invoke-ServiceRequest([uri]$serviceUrl, [string]$target) {
    if ($serviceUrl.Scheme -ne 'http' -or $serviceUrl.Port -ne $Port) {
        throw "Unexpected E2E service URL: $serviceUrl"
    }
    $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port$target")
    $request.Host = $serviceUrl.Authority
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    $response = $null
    $reader = $null
    try {
        try { $response = $request.GetResponse() }
        catch [Net.WebException] {
            if (-not $_.Exception.Response) { throw }
            $response = $_.Exception.Response
        }
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        return @{ Status = [int]$response.StatusCode; Body = $reader.ReadToEnd() }
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($response) { $response.Dispose() }
    }
}

function Test-ServiceForwarding([string]$sandboxName, [string]$readyFile, [string]$nonce) {
    if (-not (Wait-File $readyFile 30)) { throw "MXC HTTP listener did not report readiness" }
    $targetPort = [int](Get-Content -LiteralPath $readyFile -Raw).Trim()
    if ($targetPort -lt 1 -or $targetPort -gt 65535) { throw "Invalid workload HTTP port" }
    $exposed = $false
    try {
        $result = Invoke-NativeCaptured $cli @('service', 'expose', $sandboxName, "$targetPort", 'web') 15
        $text = $result.Output -join "`n"
        $text | Set-Content -LiteralPath (Join-Path $resultDir 'service.expose.log') -Encoding UTF8
        if ($result.ExitCode -ne 0) { throw "service expose failed: $text" }
        $exposed = $true
        if ($text -notmatch 'URL:\s+(http://[^\s\x1b]+)') { throw "service expose returned no HTTP URL: $text" }
        $serviceUrl = [uri]$Matches[1]
        for ($exchange = 1; $exchange -le 2; $exchange++) {
            $target = "/probe-$exchange?request=$([guid]::NewGuid().ToString('N'))"
            $response = Invoke-ServiceRequest $serviceUrl $target
            if ($response.Status -ne 200 -or $response.Body -ne "$nonce`:$target") {
                throw "HTTP exchange $exchange failed: status=$($response.Status); body=$($response.Body)"
            }
            Info "service HTTP exchange ${exchange}: exact workload response verified"
        }
        $deleted = Invoke-NativeCaptured $cli @('service', 'delete', $sandboxName, 'web') 15
        $deleted.Output | Set-Content -LiteralPath (Join-Path $resultDir 'service.delete.log') -Encoding UTF8
        if ($deleted.ExitCode -ne 0) { throw "service delete failed: $($deleted.Output -join "`n")" }
        $exposed = $false
        $response = Invoke-ServiceRequest $serviceUrl '/after-delete'
        if ($response.Status -ne 404) { throw "Deleted service still routes: status=$($response.Status)" }
        Info 'deleted service returns HTTP 404'
    } finally {
        if ($exposed) {
            try { Invoke-NativeCaptured $cli @('service', 'delete', $sandboxName, 'web') 15 | Out-Null } catch {}
        }
    }
}

# Detect an agent *launch* failure (binary not found / not implemented) vs a
# legitimate policy denial. Used to avoid false-passing a deny scenario when the
# agent never actually ran.
function Launch-Failed([string]$gwText) {
    if ($null -eq $gwText) { return $false }
    return ($gwText -match 'CreateProcessW failed error:2' `
        -or $gwText -match 'error:2' `
        -or $gwText -match 'exited -1' `
        -or $gwText -match 'The system cannot find the file' `
        -or $gwText -match 'E_NOTIMPL' `
        -or $gwText -match 'velocity')
}

function Launch-Succeeded([string]$gwText) {
    if ($null -eq $gwText) { return $false }
    return ($gwText -match 'MXC agent launched')
}

# --- Backend probe ------------------------------------------------------------

function Probe-Backend([string] $backendName, [string] $wxc) {
    if (-not (Test-Path $wxc)) { return @{ Live = $false; Reason = "wxc-exec not found at $wxc" } }

    if ($backendName -eq "process_container") {
        $probeResult = Invoke-NativeCaptured $wxc @("--probe")
        if ($probeResult.ExitCode -ne 0) { throw "MXC capability probe failed: $($probeResult.Output -join ' ')" }
        $capabilities = ($probeResult.Output -join "`n") | ConvertFrom-Json
        if (-not $capabilities.probes.baseContainerSupportsIngressHostLoopbackAllow) {
            return @{ Live = $false; Reason = "native ProcessContainer host-loopback support unavailable (processmodel PSEC contract required)" }
        }
        # Use a REAL directory + absolute cmd.exe: the canonical wxc-exec passes
        # cwd straight to CreateProcessW and does NOT expand %TEMP% (that yields
        # 0x8007010B "directory name is invalid").
        $probeDir = Join-Path $env:TEMP "mxc-e2e-probe"
        New-Item -ItemType Directory -Force $probeDir | Out-Null
        $config = @{
            version     = "1.0.0"
            containerId = "e2e-probe-pc"
            containment = "processcontainer"
            process     = @{ commandLine = "C:\Windows\System32\cmd.exe /c exit 0"; cwd = $probeDir; timeout = 30000 }  # ms (MXC process.timeout is milliseconds)
            filesystem  = @{ readwritePaths = @($probeDir) }
            processContainer = @{ leastPrivilege = $false }
        }
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Depth 20 -Compress)))
        $outObj = & $wxc --config-base64 $b64 2>&1
        $exitCode = $LASTEXITCODE
        $output = ($outObj -join "`n").ToLower()
        if ($exitCode -eq 0) { return @{ Live = $true; Reason = "process_container probe exit 0" } }
        $reason = "process_container unavailable: exit $exitCode"
        if ($output -match "backend_error" -or $output -match "e_notimpl" -or $output -match "velocity") {
            $reason = "process_container backend_error (velocity keys not enabled)"
        }
        return @{ Live = $false; Reason = $reason }
    }

    if ($backendName -eq "isolation_session") {
        $config = @{
            version     = "1.0.0"
            containment = "isolation_session"
            network     = @{
                egress  = @{ default = "allow" }
                ingress = @{ default = "allow"; hostLoopback = "allow" }
            }
        }
        $json = $config | ConvertTo-Json -Depth 20 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $b64 = [Convert]::ToBase64String($bytes)
        $outObj = & $wxc --config-base64 $b64 --operation provision 2>&1
        $exitCode = $LASTEXITCODE
        $output = ($outObj -join "`n").ToLower()
        if ($output -match "backend_unavailable" -or $output -match "0x80040154") {
            return @{ Live = $false; Reason = "isolation_session backend_unavailable (IsoSessionApp.dll absent)" }
        }
        if ($exitCode -ne 0) {
            return @{ Live = $false; Reason = "isolation_session probe failed: exit $exitCode" }
        }
        # Provision succeeded - deprovision immediately.
        $sandboxId = $null
        try {
            $rawOut = ($outObj -join "`n")
            $parsed = $rawOut | ConvertFrom-Json
            $sandboxId = $parsed.result.sandboxId
        } catch {}
        if ($null -ne $sandboxId) {
            $deprovConfig = @{ version = "1.0.0" }
            $deprovJson = $deprovConfig | ConvertTo-Json -Depth 20 -Compress
            $deprovBytes = [System.Text.Encoding]::UTF8.GetBytes($deprovJson)
            $deprovB64 = [Convert]::ToBase64String($deprovBytes)
            & $wxc --config-base64 $deprovB64 --operation deprovision --container-id $sandboxId 2>&1 | Out-Null
        }
        return @{ Live = $true; Reason = "isolation_session probe: provisioned and deprovisioned" }
    }

    return @{ Live = $false; Reason = "unknown backend: $backendName" }
}

# --- Run ----------------------------------------------------------------------
# Everything that can throw runs inside this try so the finally always produces
# the results bundle (summary + transcript + zip), even on a pre-flight failure.

$results      = @()
$gw           = $null
$harnessError = $null
$backendProbe = @{ Live = $false; Reason = "not probed" }
# Unique per-run suffix so a stale sandbox record from an earlier run can never
# collide with this run's `sandbox create` (the gateway persists names on disk).
# Sandbox names are limited to 19 characters, so keep the timestamp compact.
$runId = Get-Date -Format 'MMddHHmmss'

try {
    Enter-IsolatedCliEnvironment
    # Start the transcript inside the guarded region so a Start-Transcript failure
    # is caught and the results bundle is still produced. Pre-flight runs
    # immediately below, so the transcript still captures the whole run.
    Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null
    $transcriptStarted = $true

    # --- Pre-flight -----------------------------------------------------------

    if ($env:OPENSHELL_MXC_MOCK_WXC -eq "1") {
        throw "OPENSHELL_MXC_MOCK_WXC=1 is set. E2E requires real MXC; unset this variable."
    }

    # -KeepRunning leaves the gateway up and breaks after the FIRST scenario (so the
    # next one cannot collide on the port). A full-suite run would therefore execute
    # only one scenario yet still report the suite as PASS. Require a single,
    # explicitly-selected scenario so a partial run can never be mislabeled complete.
    if ($KeepRunning -and -not $Scenario) {
        throw "-KeepRunning requires -Scenario: it stops after the first scenario, so a full-suite run would report PASS on partial results. Re-run with e.g. -Scenario fs-rw-positive-negative -KeepRunning."
    }

    foreach ($f in @($gateway, $cli, $tomlTemplate, (Join-Path $BinaryDir 'openshell-supervisor.exe'), (Join-Path $BinaryDir 'openshell-windows-sandbox.exe'))) {
        if (-not (Test-Path $f)) {
            throw "Missing artifact: $f`nBuild first or run from a demo-package folder."
        }
    }
    if (-not (Test-Path $policyDir)) {
        throw "e2e-policies/ directory not found at $policyDir"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $BinaryDir 'libz3.dll') -PathType Leaf)) {
        throw "Missing libz3.dll beside the gateway. Re-run windows:build for this architecture, or package the matching Z3 runtime with these binaries."
    }

    # Capture the pristine TOML once; every scenario renders a fresh copy from this.
    $tomlBase = Get-Content $tomlTemplate -Raw
    $openssl = (Get-Command openssl -ErrorAction Stop).Source
    New-Item -ItemType Directory $secretDir | Out-Null
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $secretDir /inheritance:r /grant:r "*$($ownerSid):(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot protect disposable signing-key directory" }
    foreach ($argsForKey in @(
        @('genpkey', '-algorithm', 'ED25519', '-out', (Join-Path $secretDir 'signing.pem')),
        @('pkey', '-in', (Join-Path $secretDir 'signing.pem'), '-pubout', '-out', (Join-Path $secretDir 'public.pem'))
    )) {
        $keyResult = Invoke-NativeCaptured $openssl $argsForKey
        if ($keyResult.ExitCode -ne 0) { throw "disposable JWT key generation failed" }
    }
    Set-Content (Join-Path $secretDir 'kid') -Value 'mxc-e2e' -Encoding ASCII

    # --- Mode setup -----------------------------------------------------------

    Step "Pre-flight (mode=REAL, backend=$Backend)"
    $cliProbe = Invoke-NativeCaptured $cli @("--version")
    $cliProbeText = ($cliProbe.Output -join "`n")
    if ($cliProbe.ExitCode -ne 0) {
        throw "CLI pre-flight failed for '$cli' (exit $($cliProbe.ExitCode)): $cliProbeText"
    }
    Ok "CLI executable allowed: $($cliProbe.Output -join ' ')"

    Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
    $env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
    Info "wxc-exec: $WxcExecPath"

    $backendProbe = Probe-Backend -backendName $Backend -wxc $WxcExecPath
    if ($backendProbe.Live) {
        Ok "Backend '$Backend' is live: $($backendProbe.Reason)"
    } else {
        Warn "Backend '$Backend' is not live: $($backendProbe.Reason)"
        Warn "Runtime scenarios will SKIP; this is not a real-isolation PASS."
    }

    Step "Check gateway port $Port"
    if (Test-PortListening) { throw "port $Port in use. Stop stale gateway first." }
    Ok "port $Port free"

    Step "Prepare DemoDir + read-only source + deny-probe dir"
    New-Item -ItemType Directory -Force $DemoDir   | Out-Null
    New-Item -ItemType Directory -Force $roSrc     | Out-Null
    New-Item -ItemType Directory -Force $denyProbe | Out-Null
    Set-Content -Path (Join-Path $roSrc "seed.txt") -Value "read-only seed" -Encoding UTF8
    Ok "DemoDir=$DemoDir  roSrc=$roSrc  denyProbe=$denyProbe"

    $env:OPENSHELL_COMPUTE_DRIVER = "mxc"
    $env:OPENSHELL_MXC_SHARE_DIR = $DemoDir

    # --- Scenario definitions -------------------------------------------------
    #   Kind: positive | deny
    #   For deny: ControlTarget (granted, must be PRESENT) + DenyTarget (must be ABSENT).

    $allScenarios = @(
        @{
            Name = "fs-rw"; PolicyFile = Join-Path $policyDir "fs-rw.yaml"
            SandboxId = "rw"
            Backends = "both"; Kind = "positive"
            PosTarget = (Join-Path $DemoDir "fs-rw-result.txt")
            Description = "rw grant on DemoDir; in-policy write should succeed"
        },
        @{
            Name = "fs-readonly"; PolicyFile = Join-Path $policyDir "fs-readonly.yaml"
            SandboxId = "ro"
            Backends = "both"; Kind = "deny"
            ControlTarget = (Join-Path $DemoDir "fs-readonly-control.txt")
            DenyTarget    = (Join-Path $roSrc  "fs-readonly-denied.txt")
            Description = "write to read-only dir denied; control write to rw dir succeeds"
        },
        @{
            Name = "fs-default-deny"; PolicyFile = Join-Path $policyDir "fs-empty.yaml"
            SandboxId = "fd"
            Backends = "process_container"; Kind = "deny"
            DenyTarget    = (Join-Path $denyProbe "fs-default-deny-denied.txt")
            Description = "empty policy; ungranted write denied"
        },
        @{
            Name = "network-policy"; PolicyFile = Join-Path $policyDir "network-reject.yaml"
            SandboxId = "net"
            Backends = "both"; Kind = "positive"
            PosTarget = (Join-Path $DemoDir "network-policy-result.txt")
            Description = "supervisor-owned network policy is accepted and workload runs (not an egress assertion)"
        },
        @{
            Name = "forwarding"; PolicyFile = Join-Path $policyDir "forwarding.yaml"
            SandboxId = "fwd"
            Backends = "process_container"; Kind = "forwarding"
            ReadyFile = (Join-Path $DemoDir "forwarding-port.txt")
            Description = "real MXC listener receives two TCP exchanges through authenticated OpenShell forwarding"
        },
        @{
            Name = "service-forwarding"; PolicyFile = Join-Path $policyDir "forwarding.yaml"
            SandboxId = "svc"
            Backends = "process_container"; Kind = "service-forwarding"
            ReadyFile = (Join-Path $DemoDir "service-forwarding-port.txt")
            Description = "named HTTP service routes two requests into MXC and stops routing after deletion"
        }
    )

    if ($Scenario) {
        # Wrap in @() so an exact single match stays an array: without it a lone
        # match is a bare hashtable, its .Count is unreliable on PS 5.1, and
        # $allScenarios would no longer be an array for the loop below.
        $filtered = @($allScenarios | Where-Object { $_.Name -eq $Scenario })
        if ($filtered.Count -eq 0) {
            throw "Scenario '$Scenario' not found. Available: $(($allScenarios | ForEach-Object { $_.Name }) -join ', ')"
        }
        $allScenarios = $filtered
    }

    # --- Scenario loop --------------------------------------------------------

    try {
        foreach ($sc in $allScenarios) {
            Step "Scenario: $($sc.Name)"
            Info $sc.Description

            $skipReason = $null
            $backendMatches = ($sc.Backends -eq "both") -or ($sc.Backends -eq $Backend)
            if (-not $backendMatches) {
                $skipReason = "scenario requires backend=$($sc.Backends); current backend=$Backend"
            } elseif (-not $backendProbe.Live) {
                $skipReason = "backend not live: $($backendProbe.Reason)"
            }
            if ($null -ne $skipReason) {
                Skip "$($sc.Name): $skipReason"
                $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "SKIP"; Reason = $skipReason }
                continue
            }

            if (-not (Test-Path $sc.PolicyFile)) {
                Bad "$($sc.Name): policy fixture not found at $($sc.PolicyFile)"
                $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "policy fixture missing" }
                continue
            }

            # Render a disposable policy for every scenario. The source YAML
            # intentionally carries the documented default paths, while
            # -DemoDir is a supported override. Both the read-write path and
            # the read-only sibling share the same default prefix, so one
            # exact prefix substitution keeps their relative naming intact.
            $policyUsed = Join-Path $resultDir "policy.$($sc.Name).yaml"
            $policyText = Get-Content $sc.PolicyFile -Raw
            $policyText = $policyText.Replace(
                $defaultDemoDir.Replace('\', '/'),
                $DemoDir.Replace('\', '/')
            )
            Set-Content -Path $policyUsed -Value $policyText -Encoding UTF8

            # Per-scenario gateway logs land in the bundle under their own names.
            $gwLog    = Join-Path $resultDir "gateway.$($sc.Name).log"
            $gwErrLog = Join-Path $resultDir "gateway.$($sc.Name).err.log"

            # Build the per-sandbox workload command and clean prior artifacts.
            if ($sc.Kind -eq "positive") {
                Remove-Item $sc.PosTarget -Force -ErrorAction SilentlyContinue
                $command = @($cmdExe, "/c", "echo ok 1> $($sc.PosTarget.Replace('\', '/'))")
            } elseif ($sc.Kind -eq "deny") {
                Remove-Item $sc.DenyTarget -Force -ErrorAction SilentlyContinue
                $denied = $sc.DenyTarget.Replace('\', '/')
                if ($sc.ControlTarget) {
                    Remove-Item $sc.ControlTarget -Force -ErrorAction SilentlyContinue
                    $control = $sc.ControlTarget.Replace('\', '/')
                    $command = @($cmdExe, "/c", "echo denied 1> $denied & echo ok 1> $control")
                } else {
                    $command = @($cmdExe, "/c", "echo denied 1> $denied")
                }
            } elseif ($sc.Kind -in @("forwarding", "service-forwarding")) {
                Remove-Item -LiteralPath $sc.ReadyFile -Force -ErrorAction SilentlyContinue
                $forwardNonce = [guid]::NewGuid().ToString('N')
                $fixture = Join-Path $BinaryDir 'mxc-forwarding-agent.exe'
                if (-not (Test-Path -LiteralPath $fixture)) {
                    $fixture = Join-Path $BinaryDir 'examples/mxc-forwarding-agent.exe'
                }
                if (-not (Test-Path -LiteralPath $fixture)) {
                    throw "Missing forwarding fixture; run mise run --skip-tools windows:build:mxc-fixtures"
                }
                $workload = Join-Path $DemoDir 'mxc-forwarding-agent.exe'
                Copy-Item -LiteralPath $fixture -Destination $workload -Force
                $command = @($workload, $sc.ReadyFile, $forwardNonce)
                if ($sc.Kind -eq "service-forwarding") { $command += 'http' }
            } else {
                $command = @($cmdExe, "/c", "exit 0")
            }

            $driverConfig = @{
                mxc = @{
                    command = $command
                    cwd = $demoDirFwd
                }
            } | ConvertTo-Json -Compress -Depth 4

            Render-Toml
            # Preserve the exact rendered config + policy fixture used for this scenario.
            Copy-Item $toml (Join-Path $resultDir "mxc-gateway.$($sc.Name).toml") -Force -ErrorAction SilentlyContinue
            # policyUsed already lives in the result bundle and is the exact
            # rendered policy passed to OpenShell.

            $gw = Start-Gw
            Info "gateway pid $($gw.Id)"
            Register-Cli

            # Unique per-run sandbox name within the 19-character routable-name limit.
            $sandboxName = "mxc-$($sc.SandboxId)-$runId"
            try { Invoke-NativeCaptured $cli @("sandbox", "delete", $sandboxName) | Out-Null } catch {}

            # Run sandbox create; require artifact evidence for live workload tests.
            $createOut = $null; $createExitCode = 0
            try {
                $createResult = Invoke-NativeCaptured $cli @(
                    "sandbox", "create", "--name", $sandboxName,
                    "--policy", [string]$policyUsed,
                    "--driver-config-json", $driverConfig,
                    "--no-tty"
                )
                $createOut = $createResult.Output
                $createExitCode = $createResult.ExitCode
            } catch {
                $createOut = $_.Exception.Message; $createExitCode = 1
            }
            $createOutStr = ($createOut -join "`n")
            Info "create exit: $createExitCode"

            $gwText = (Get-Content $gwLog, $gwErrLog -Raw -ErrorAction SilentlyContinue) -join "`n"

            # Evaluate.
            if ($sc.Kind -eq "positive") {
                $present = Wait-File $sc.PosTarget 30
                if ($present -and $createExitCode -eq 0) {
                    Ok "$($sc.Name): in-policy write produced artifact"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "artifact present" }
                } else {
                    Bad "$($sc.Name): artifact absent ($($sc.PosTarget))"
                    Info "createOut: $createOutStr"
                    if (Launch-Failed $gwText) { Info "gateway log shows an agent-launch failure (not a policy result)" }
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "artifact absent" }
                }
            } elseif ($sc.Kind -in @("forwarding", "service-forwarding")) {
                try {
                    if ($createExitCode -ne 0) { throw "sandbox create failed: $createOutStr" }
                    if ($sc.Kind -eq 'forwarding') {
                        Test-Forwarding $sandboxName $sc.ReadyFile $forwardNonce
                        $reason = 'two exact TCP replies through OpenShell'
                    } else {
                        Test-ServiceForwarding $sandboxName $sc.ReadyFile $forwardNonce
                        $reason = 'two exact HTTP replies; deleted route returns 404'
                    }
                    Ok "$($sc.Name): $reason"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = $reason }
                } catch {
                    Bad "$($sc.Name): $($_.Exception.Message)"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = $_.Exception.Message }
                    try {
                        $diagnostic = Invoke-NativeCaptured $cli @('sandbox', 'get', $sandboxName, '-o', 'json') 5
                        $diagnostic.Output | Set-Content -LiteralPath (Join-Path $resultDir 'forward.sandbox.json') -Encoding UTF8
                        Info "sandbox state captured in forward.sandbox.json"
                    } catch { Info "sandbox diagnostics unavailable: $($_.Exception.Message)" }
                }
            } else {
                # deny
                if ($sc.ControlTarget) {
                    $controlPresent = Wait-File $sc.ControlTarget 30
                    # Snapshot the deny target only AFTER the control artifact lands, so a
                    # late denied write (enforcement regression racing the control write)
                    # cannot be recorded as PASS.
                    $denyPresent = Test-Path $sc.DenyTarget
                    if ($controlPresent -and -not $denyPresent) {
                        Ok "$($sc.Name): control write succeeded; denied write correctly blocked"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "control present, deny absent" }
                    } elseif (-not $controlPresent) {
                        Bad "$($sc.Name): control write absent - agent did not run correctly (inconclusive denial)"
                        Info "createOut: $createOutStr"
                        if (Launch-Failed $gwText) { Info "gateway log shows an agent-launch failure" }
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "control absent (agent did not run)" }
                    } else {
                        Bad "$($sc.Name): denied write was NOT blocked (artifact present)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "deny target present (not enforced)" }
                    }
                } else {
                    # An empty policy has no writable control path. Require both an absent
                    # artifact and an explicit driver launch message so launch failures
                    # cannot false-pass the denial.
                    Start-Sleep -Seconds 3
                    $denyPresent = Test-Path $sc.DenyTarget
                    $gwText = (Get-Content $gwLog, $gwErrLog -Raw -ErrorAction SilentlyContinue) -join "`n"
                    if ($denyPresent) {
                        Bad "$($sc.Name): denied write was NOT blocked (artifact present)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "deny target present (not enforced)" }
                    } elseif (Launch-Failed $gwText) {
                        Bad "$($sc.Name): artifact absent but agent failed to launch - inconclusive"
                        Info "createOut: $createOutStr"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "agent launch failed (inconclusive)" }
                    } elseif (-not (Launch-Succeeded $gwText)) {
                        Bad "$($sc.Name): artifact absent but no agent-launch evidence was recorded - inconclusive"
                        Info "createOut: $createOutStr"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "agent launch not confirmed (inconclusive)" }
                    } else {
                        Ok "$($sc.Name): write correctly denied (artifact absent, agent launched)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "deny absent (default-deny enforced)" }
                    }
                }
            }

            if ($KeepRunning) {
                Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stopping after the first scenario so the next one doesn't collide on port $Port"
                break
            } else {
                # Keep the sandbox alive until artifact-based scoring finishes.
                # Real MXC startup is asynchronous and can otherwise be canceled
                # before the workload writes its positive/control proof.
                try { Invoke-NativeCaptured $cli @("sandbox", "delete", $sandboxName) | Out-Null } catch {}
                Stop-Gw $gw
                $gw = $null
            }
        }
    } finally {
        if ($gw -and -not $KeepRunning) { Stop-Gw $gw }
        if ($KeepRunning -and $gw) { Info "gateway pid $($gw.Id) left running (-KeepRunning)" }
    }
}
catch {
    $harnessError = $_.Exception.Message
    Bad "harness error: $harnessError"
}
finally {
    # --- Summary + results bundle ---------------------------------------------
    Step "Summary"
    $results | Format-Table -AutoSize

    # Wrap in @() so a single match still yields an array with a .Count (PS 5.1).
    $failCount = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
    $passCount = @($results | Where-Object { $_.Result -eq "PASS" }).Count
    $skipCount = @($results | Where-Object { $_.Result -eq "SKIP" }).Count
    Write-Host "PASS=$passCount  FAIL=$failCount  SKIP=$skipCount"

    $verdict = if ($harnessError -or $failCount -gt 0) { "FAIL" } elseif ($passCount -eq 0 -or $skipCount -gt 0) { "INCOMPLETE" } else { "PASS" }
    $tableText = ($results | Format-Table -AutoSize | Out-String)
    $summary = @"
OpenShell MXC e2e scenario run
==============================
timestamp    : $stamp
machine      : $env:COMPUTERNAME
verdict      : $verdict
mode         : REAL
backend      : $Backend
backend_live : $($backendProbe.Live)   ($($backendProbe.Reason))
wxc_exec     : $WxcExecPath
gateway_port : $Port
totals       : PASS=$passCount  FAIL=$failCount  SKIP=$skipCount
$(if ($harnessError) { "harness_error: $harnessError" })

Per-scenario results:
$tableText
Files in this bundle ($resultDir):
  summary.txt                        this summary
  transcript.txt                     full console transcript
  gateway.<scenario>.log / .err.log  per-scenario gateway stdout/stderr
  mxc-gateway.<scenario>.toml        the exact gateway config rendered per scenario
  policy.<scenario>.yaml             the exact sandbox policy fixture used per scenario

What PASS means: every selected scenario ran against real MXC and met its expected verdict - positive
writes produced their artifact, deny writes were blocked with either a control
write or driver-launch evidence, and forwarding verified two exact TCP replies
through OpenShell. Service forwarding verifies two HTTP replies and HTTP 404
after endpoint deletion. Missing coverage exits non-zero; network-policy proves
admission and execution, not network enforcement. Forwarding proves managed
ingress works, not that direct host ingress is blocked.
"@
    Set-Content -Path (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
    Write-Host $summary -ForegroundColor ($(if ($verdict -eq "PASS") { "Green" } else { "Red" }))

    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }

    # Zip the bundle for easy return (defensive; never throw out of finally).
    try {
        $zip = Join-Path $resultsRoot "results-e2e-$stamp.zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
        Write-Host "`nResults bundle: $zip" -ForegroundColor Yellow
    } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }
    if (-not ($KeepRunning -and $gw)) {
        foreach ($keyFile in @('signing.pem', 'public.pem', 'kid')) {
            Remove-Item -LiteralPath (Join-Path $secretDir $keyFile) -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $secretDir) { Remove-Item -LiteralPath $secretDir -ErrorAction SilentlyContinue }
    }
    Exit-IsolatedCliEnvironment
    foreach ($name in $savedEnv.Keys) {
        $snapshot = $savedEnv[$name]
        Set-ProcessEnvironmentVariableExact -Name $name -Exists $snapshot.Exists -Value $snapshot.Value
    }
}

if ($harnessError -or $failCount -gt 0) {
    Write-Host "`nSOME SCENARIOS FAILED" -ForegroundColor Red
    exit 1
} elseif ($passCount -eq 0 -or $skipCount -gt 0) {
    Write-Host "`nE2E INCOMPLETE: PASS=$passCount SKIP=$skipCount - real runtime coverage required" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "`nALL SELECTED REAL MXC SCENARIOS PASSED: PASS=$passCount" -ForegroundColor Green
    exit 0
}
