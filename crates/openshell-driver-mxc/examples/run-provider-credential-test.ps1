# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end MXC provider credential scenario.
#
# The sandbox receives a revision-scoped GITHUB_TOKEN placeholder, never the
# raw token. The MXC host CONNECT proxy resolves it for api.github.com and
# rejects the same placeholder at policy-allowed github.com because that host is
# outside this test profile's sole api.github.com credential binding.
#
# Prerequisites:
#   $env:GITHUB_TOKEN = "github_pat_..."
#   mise run --skip-tools windows:build:x64
#
# Run from a local demo-package folder containing openshell-gateway.exe,
# openshell.exe, the PowerShell probe, and the three configuration fixtures
# beside this script, or pass explicit local gateway and CLI paths. When the
# script is copied to a network share, keep the executables on a local volume;
# Windows Application Control commonly rejects unsigned development binaries
# launched from UNC or mapped network paths.
#
#   powershell -NoProfile -ExecutionPolicy Bypass `
#     -File .\run-provider-credential-test.ps1 `
#     -GatewayPath .\target\x86_64-pc-windows-msvc\release\openshell-gateway.exe `
#     -CliPath .\target\x86_64-pc-windows-msvc\release\openshell.exe
#
# PowerShell 5.1-compatible. The script never prints GITHUB_TOKEN and scans all
# result artifacts for accidental raw-token leakage before creating the bundle.

[CmdletBinding()]
param(
    [string] $ShareDir     = "C:\work\openshell-mxc-provider",
    [string] $WxcExecPath  = "C:\mxc-kit\bin\wxc-exec.exe",
    [string] $GatewayPath,
    [string] $CliPath,
    [int]    $Port         = 17670,
    [string] $GatewayName  = "openshell-mxc-provider-e2e"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-provider-credential-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null

function Step([string]$message) {
    $script:failureStage = $message
    Write-Host "`n=== $message ===" -ForegroundColor Cyan
}
function Info([string]$message) { Write-Host "    $message" }
function Ok([string]$message) { Write-Host "[OK]   $message" -ForegroundColor Green }
function Bad([string]$message) { Write-Host "[FAIL] $message" -ForegroundColor Red }

function Resolve-Artifact([string]$explicit, [string]$leaf) {
    if (-not [string]::IsNullOrWhiteSpace($explicit)) {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($explicit)
    }
    return (Join-Path $here $leaf)
}

function Escape-Toml([string]$value) { return $value.Replace('\', '\\') }

function Test-NetworkPath([string]$value) {
    if ($value.StartsWith('\\')) { return $true }
    if ($value -notmatch '^([A-Za-z]):[\\/]') { return $false }

    $drive = Get-PSDrive -Name $Matches[1] -PSProvider FileSystem -ErrorAction SilentlyContinue
    return $null -ne $drive -and
        -not [string]::IsNullOrWhiteSpace($drive.DisplayRoot) -and
        $drive.DisplayRoot.StartsWith('\\')
}

function Assert-LocalExecutable([string]$label, [string]$path) {
    if (-not (Test-NetworkPath $path)) { return }

    throw "$label executable resolves to network path '$path'. Windows Application Control can block unsigned development binaries launched from network locations. Pass -GatewayPath and -CliPath pointing to local build outputs (for example, the repository's target\x86_64-pc-windows-msvc\release directory); the script and result artifacts may remain on the network share."
}

function Get-LaunchFailureMessage([string]$label, [string]$path, [System.Exception]$exception) {
    $messages = New-Object System.Collections.Generic.List[string]
    $currentException = $exception
    while ($null -ne $currentException) {
        if (-not [string]::IsNullOrWhiteSpace($currentException.Message)) {
            [void]$messages.Add($currentException.Message)
        }
        $currentException = $currentException.InnerException
    }
    $message = ($messages -join ' | ')

    if ($message -match '(?i)Application Control policy has blocked this file') {
        $sha256 = try { (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { "unavailable" }
        $signature = try { (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status } catch { "unavailable" }
        return "Application Control blocked $label launch '$path' (SHA256=$sha256; Authenticode=$signature). Use a local, policy-approved binary and review the applicable App Control event log if the local launch is also blocked. Original error: $message"
    }

    return "failed to launch $label '$path': $message"
}

# Build one CreateProcess-compatible command-line argument. Windows PowerShell
# 5.1 removes embedded quotes from JSON passed to native commands through the
# call operator, which corrupts --driver-config-json before the CLI parses it.
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

function Invoke-Cli([string[]]$CommandArgs, [switch]$AllowFailure) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $cli
    $startInfo.Arguments = (($CommandArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "failed to start $cli" }
    } catch {
        throw (Get-LaunchFailureMessage "CLI" $cli $_.Exception)
    }

    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $text = (@($stdout.Result, $stderr.Result) | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }) -join [Environment]::NewLine
    $text = $text.Trim()
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "openshell $($CommandArgs -join ' ') failed (exit $exitCode): $text"
    }
    return @{ ExitCode = $exitCode; Text = $text }
}

function Wait-ForProbeResult([string]$path, [string]$sandbox, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $path)) {
        $status = Invoke-Cli @("sandbox", "get", $sandbox, "--output", "json") -AllowFailure
        if ($status.ExitCode -eq 0) {
            $details = $null
            try { $details = $status.Text | ConvertFrom-Json } catch {}
            if ($details -and $details.phase -eq "Error") {
                throw "sandbox $sandbox entered Error before producing the probe result; inspect $gwLog and $gwErrLog"
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return (Test-Path $path)
}

function Copy-ProbeArtifacts {
    $artifacts = @(
        @{ Source = $resultFile; Destination = "mxc-provider-credential-result.txt" },
        @{ Source = (Join-Path $ShareDir "github-user-response.json"); Destination = "github-user-response.json" },
        @{ Source = (Join-Path $ShareDir "credential-mismatch-response.json"); Destination = "credential-mismatch-response.json" }
    )
    foreach ($artifact in $artifacts) {
        if (Test-Path $artifact.Source) {
            Copy-Item $artifact.Source (Join-Path $resultDir $artifact.Destination) -Force
        }
    }
}

$gateway = Resolve-Artifact $GatewayPath "openshell-gateway.exe"
$cli = Resolve-Artifact $CliPath "openshell.exe"
$powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$probeTemplate = Join-Path $here "mxc-provider-credential-probe.ps1"
$tomlTemplate = Join-Path $here "mxc-provider-credential.toml"
$policyTemplate = Join-Path $here "mxc-provider-credential-policy.yaml"
$profileTemplate = Join-Path $here "mxc-github-provider-profile.yml"
$tomlUsed = Join-Path $resultDir "mxc-provider-credential.used.toml"
$policyUsed = Join-Path $resultDir "mxc-provider-credential-policy.used.yaml"
$profileUsed = Join-Path $resultDir "mxc-github-provider-profile.used.yml"
$resultFile = Join-Path $ShareDir "mxc-provider-credential-result.txt"
$wxcProbeFile = Join-Path $resultDir "wxc-probe.json"
$gwLog = Join-Path $resultDir "gateway.log"
$gwErrLog = Join-Path $resultDir "gateway.err.log"
$gw = $null
$sandboxName = "mxc-gh-$(Get-Date -Format 'MMddHHmmss')"
$providerName = "mxc-github-e2e"
$passed = $false
$rawTokenLeak = $false
$artifactScanFailed = $false
$failureReason = ""
$failureStage = "initialization"
$githubToken = $env:GITHUB_TOKEN

try {
    Step "Validate prerequisites"
    if ([string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
        throw "GITHUB_TOKEN is not set. Set it in this PowerShell session; do not pass it on the command line."
    }
    foreach ($file in @($gateway, $cli, $powerShellExe, $probeTemplate, $tomlTemplate, $policyTemplate, $profileTemplate, $WxcExecPath)) {
        if (-not (Test-Path $file)) { throw "missing artifact: $file" }
        Info "found $file"
    }
    Assert-LocalExecutable "gateway" $gateway
    Assert-LocalExecutable "CLI" $cli
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
        throw "gateway port $Port is already in use"
    }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $wxcProbeLines = & $WxcExecPath --probe 2>&1
        $wxcProbeExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $wxcProbeText = (($wxcProbeLines | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        } else {
            $_.ToString()
        }
    }) -join [Environment]::NewLine).Trim()
    [System.IO.File]::WriteAllText($wxcProbeFile, $wxcProbeText, $utf8NoBom)
    if ($wxcProbeExit -ne 0) {
        throw "wxc-exec --probe failed (exit $wxcProbeExit); inspect $wxcProbeFile"
    }
    Ok "prerequisites available; token value was not printed"

    Step "Render disposable config and stage probe"
    $shareFwd = $ShareDir.Replace('\', '/')
    $powerShellFwd = $powerShellExe.Replace('\', '/')
    New-Item -ItemType Directory -Force $ShareDir | Out-Null
    $stagedProbe = Join-Path $ShareDir "mxc-provider-credential-probe.ps1"
    Copy-Item $probeTemplate $stagedProbe -Force
    Remove-Item `
        $resultFile, `
        (Join-Path $ShareDir "github-user-response.json"), `
        (Join-Path $ShareDir "credential-mismatch-response.json"), `
        (Join-Path $ShareDir "github-user-response.json.stderr"), `
        (Join-Path $ShareDir "credential-mismatch-response.json.stderr") `
        -Force -ErrorAction SilentlyContinue

    $tomlText = [System.IO.File]::ReadAllText($tomlTemplate, [System.Text.Encoding]::UTF8)
    $tomlText = [regex]::Replace(
        $tomlText,
        '(?m)^wxc_exec_path\s*=.*$',
        "wxc_exec_path = `"$(Escape-Toml $WxcExecPath)`""
    )
    [System.IO.File]::WriteAllText($tomlUsed, $tomlText, $utf8NoBom)

    $policyText = [System.IO.File]::ReadAllText($policyTemplate, [System.Text.Encoding]::UTF8).Replace("C:/work/openshell-mxc-provider", $shareFwd)
    $policyText = $policyText.Replace("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", $powerShellFwd)
    [System.IO.File]::WriteAllText($policyUsed, $policyText, $utf8NoBom)
    $profileText = [System.IO.File]::ReadAllText($profileTemplate, [System.Text.Encoding]::UTF8)
    $profileText = $profileText.Replace("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", $powerShellFwd)
    [System.IO.File]::WriteAllText($profileUsed, $profileText, $utf8NoBom)
    $driverConfig = @{
        mxc = @{
            command = @(
                $powerShellFwd,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "$shareFwd/mxc-provider-credential-probe.ps1",
                $shareFwd
            )
            cwd = $shareFwd
        }
    } | ConvertTo-Json -Compress -Depth 4
    Ok "staged probe and rendered config without credential material"

    Step "Start gateway"
    $env:OPENSHELL_DRIVERS = "mxc"
    $env:OPENSHELL_GATEWAY_CONFIG = $tomlUsed
    Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
    # The CLI, not the gateway process environment, supplies the provider
    # credential. Temporarily remove GITHUB_TOKEN while spawning the gateway so
    # a successful test cannot be attributed to gateway environment inheritance.
    Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
    try {
        try {
            $gw = Start-Process -FilePath $gateway `
                -ArgumentList @("--disable-tls", "--db-url", "sqlite::memory:", "--log-level", "info") `
                -WorkingDirectory $here -PassThru -NoNewWindow `
                -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
        } catch {
            throw (Get-LaunchFailureMessage "gateway" $gateway $_.Exception)
        }
    } finally {
        $env:GITHUB_TOKEN = $githubToken
    }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($gw.HasExited) { throw "gateway exited early (code $($gw.ExitCode))" }
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Milliseconds 400
    }
    if (-not (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)) {
        throw "gateway did not listen on port $Port within 30 seconds"
    }
    Ok "gateway listening on 127.0.0.1:$Port"

    Step "Configure provider and effective policy"
    $env:OPENSHELL_GATEWAY = ""
    $gatewayAdd = Invoke-Cli @(
        "gateway", "add", "http://127.0.0.1:$Port", "--local", "--name", $GatewayName
    ) -AllowFailure
    if ($gatewayAdd.ExitCode -ne 0 -and $gatewayAdd.Text -notmatch '(?i)already exists') {
        throw "gateway registration failed (exit $($gatewayAdd.ExitCode)): $($gatewayAdd.Text)"
    }
    Invoke-Cli @("gateway", "select", $GatewayName) | Out-Null
    Invoke-Cli @("provider", "profile", "lint", "--file", $profileUsed) | Out-Null
    Invoke-Cli @("provider", "profile", "import", "--file", $profileUsed) | Out-Null
    Invoke-Cli @("provider", "create", "--name", $providerName, "--type", "mxc-github-e2e", "--credential", "GITHUB_TOKEN") | Out-Null
    Ok "created attached-provider inputs without adding GITHUB_TOKEN to the sandbox environment"

    Step "Create MXC sandbox and run credential probe"
    # MXC launches the per-sandbox command itself and exposes no supervisor/SSH
    # relay. Structured output makes the CLI return after the sandbox reaches
    # Ready instead of trying to connect or exec a command.
    $createArgs = @(
        "sandbox", "create",
        "--name", $sandboxName,
        "--provider", $providerName,
        "--policy", $policyUsed,
        "--driver-config-json", $driverConfig,
        # PowerShell uses SystemRoot to locate inbox curl.exe and PATHEXT to
        # recognize the fully qualified path as an executable command.
        "--env", "SystemRoot=$env:SystemRoot",
        "--env", "PATHEXT=$env:PATHEXT",
        "--env", "USERPROFILE=$shareFwd",
        "--env", "LOCALAPPDATA=$shareFwd",
        "--env", "TEMP=$shareFwd",
        "--env", "TMP=$shareFwd",
        "--output", "json"
    )
    $create = Invoke-Cli $createArgs
    if ($create.Text) { Info $create.Text }
    if (-not (Wait-ForProbeResult $resultFile $sandboxName 150)) {
        throw "probe did not produce $resultFile within 150 seconds"
    }
    $resultText = [System.IO.File]::ReadAllText($resultFile, [System.Text.Encoding]::UTF8)
    if (-not [string]::IsNullOrWhiteSpace($githubToken) -and $resultText.Contains($githubToken)) {
        $rawTokenLeak = $true
        $resultText = $resultText.Replace($githubToken, "***REDACTED***")
        [System.IO.File]::WriteAllText($resultFile, $resultText, $utf8NoBom)
    }
    Write-Host $resultText
    if ($resultText -notmatch 'OVERALL: PASS') {
        throw "in-sandbox provider credential checks failed"
    }

    $effective = Invoke-Cli @("policy", "get", $sandboxName, "--full", "--output", "json")
    [System.IO.File]::WriteAllText((Join-Path $resultDir "effective-policy.json"), $effective.Text, $utf8NoBom)
    if ($effective.Text -notmatch '_provider_mxc_github_e2e' -or $effective.Text -notmatch 'api\.github\.com') {
        throw "effective policy did not contain the attached provider's GitHub rule"
    }
    $passed = $true
    Ok "placeholder isolation, authorized rewrite, and endpoint mismatch all passed"
}
catch {
    $failureReason = ($_.Exception.Message -replace '\r?\n', ' | ').Trim()
    if (-not [string]::IsNullOrWhiteSpace($githubToken)) {
        $failureReason = $failureReason.Replace($githubToken, "***REDACTED***")
    }
    Bad $failureReason
}
finally {
    if ($cli -and $sandboxName -and $gw -and -not $gw.HasExited) {
        try { Invoke-Cli @("sandbox", "delete", $sandboxName) -AllowFailure | Out-Null } catch {}
    }

    if ($gw -and -not $gw.HasExited) {
        Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
        try { $gw.WaitForExit(5000) | Out-Null } catch {}
    }

    # Preserve probe output on both success and failure. These files contain
    # response bodies and redacted diagnostics, never the raw provider token.
    try { Copy-ProbeArtifacts } catch { Info "could not collect probe artifacts: $($_.Exception.GetType().Name)" }

    # Scan after the gateway exits so redirected log handles are flushed and
    # closed. Any match is redacted and turns the scenario into a failure.
    if (-not [string]::IsNullOrWhiteSpace($githubToken)) {
        Get-ChildItem $resultDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $artifact = $_
            try {
                $contents = [System.IO.File]::ReadAllText($artifact.FullName, [System.Text.Encoding]::UTF8)
                if ($contents.Contains($githubToken)) {
                    $rawTokenLeak = $true
                    [System.IO.File]::WriteAllText($artifact.FullName, $contents.Replace($githubToken, "***REDACTED***"), $utf8NoBom)
                }
            } catch {
                $artifactScanFailed = $true
                $passed = $false
                Bad "could not inspect result artifact $($artifact.FullName): $($_.Exception.GetType().Name)"
            }
        }
    }
    if ($rawTokenLeak) {
        $passed = $false
        Bad "raw GITHUB_TOKEN appeared in a result artifact; it was redacted"
    }

    $verdict = if ($passed) { "PASS" } else { "FAIL" }
    $summary = @"
OpenShell MXC provider credential example
=========================================
verdict    : $verdict
sandbox    : $sandboxName
backend    : process_container
provider   : $providerName
share_path : $ShareDir
stage      : $failureStage
failure    : $(if ([string]::IsNullOrWhiteSpace($failureReason)) { "none" } else { $failureReason })

PASS proves:
  - MXC received a revision-scoped GITHUB_TOKEN placeholder, not the token.
  - api.github.com accepted the credential after host-proxy substitution.
  - policy-allowed github.com could not resolve the api.github.com-bound placeholder.
  - the raw token did not appear in collected result artifacts.
"@
    [System.IO.File]::WriteAllText((Join-Path $resultDir "summary.txt"), $summary, $utf8NoBom)
    Write-Host "`n$summary" -ForegroundColor ($(if ($passed) { "Green" } else { "Red" }))

    if ($artifactScanFailed) {
        Info "result bundle was not created because one or more artifacts could not be scanned"
    } else {
        try {
            $zip = Join-Path $here "results-provider-credential-$stamp.zip"
            Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
            Write-Host "BUNDLE: $zip" -ForegroundColor Yellow
        } catch { Info "could not create result bundle: $($_.Exception.Message)" }
    }
}

if ($passed) { exit 0 } else { exit 1 }
