# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# In-sandbox probe for the MXC provider-credential example. The probe verifies
# that GITHUB_TOKEN is a revision-scoped placeholder before making any network
# request, then exercises authorized substitution and endpoint mismatch.

[CmdletBinding()]
param(
    [string] $OutputDir = "C:\work\openshell-mxc-provider"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$resultPath = Join-Path $OutputDir "mxc-provider-credential-result.txt"

function Complete-Probe([string[]] $Checks) {
    $passed = @($Checks | Where-Object { $_.StartsWith("[FAIL]") }).Count -eq 0
    $lines = @($Checks) + "OVERALL: $(if ($passed) { 'PASS' } else { 'FAIL' })"
    $summary = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($resultPath, $summary, $utf8NoBom)
    Write-Output $summary.TrimEnd()
    if ($passed) { exit 0 } else { exit 1 }
}

function Get-SafeProbeText([string] $Text, [string] $Token) {
    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $safe = $Text
    if (-not [string]::IsNullOrEmpty($Token)) {
        $safe = $safe.Replace($Token, "<credential-placeholder>")
    }
    $safe = [regex]::Replace(
        $safe,
        '(?i)(authorization:\s*bearer\s+)\S+',
        '$1<redacted>'
    )
    $safe = ($safe -replace '\r?\n', ' | ').Trim()
    if ($safe.Length -gt 512) {
        $safe = $safe.Substring(0, 512) + "..."
    }
    return $safe
}

function Invoke-CurlProbe(
    [string] $CurlPath,
    [string] $Url,
    [string] $BodyPath,
    [string] $CaBundle,
    [string] $Token
) {
    Remove-Item $BodyPath -Force -ErrorAction SilentlyContinue

    # Windows inbox curl uses Schannel, which ignores CURL_CA_BUNDLE as an
    # environment variable. Pass the host proxy's generated bundle explicitly.
    # Windows PowerShell also turns native stderr into ErrorRecord objects; use
    # Continue locally and merge stderr into memory so curl failures become
    # structured probe results. Avoid redirecting stderr to the shared folder:
    # a file created by an earlier sandbox can carry a different AppContainer
    # SID and cause PowerShell to throw UnauthorizedAccessException before curl
    # starts.
    $nativeOutput = @()
    $exitCode = -1
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $nativeOutput = @(& $CurlPath `
            --silent `
            --show-error `
            --connect-timeout 15 `
            --max-time 60 `
            --cacert $CaBundle `
            --ssl-revoke-best-effort `
            --output $BodyPath `
            --write-out "%{http_code}" `
            --header "Authorization: Bearer $Token" `
            --header "Accept: application/vnd.github+json" `
            --header "User-Agent: openshell-mxc-provider-credential-example" `
            $Url 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $stdout = @($nativeOutput | Where-Object {
        $_ -isnot [System.Management.Automation.ErrorRecord]
    } | ForEach-Object { $_.ToString() })
    $nativeErrors = @($nativeOutput | Where-Object {
        $_ -is [System.Management.Automation.ErrorRecord]
    } | ForEach-Object { $_.Exception.Message })
    $httpCode = ($stdout -join "").Trim()
    $stderr = Get-SafeProbeText `
        -Text ($nativeErrors -join [Environment]::NewLine) `
        -Token $Token
    $body = if (Test-Path $BodyPath) {
        [System.IO.File]::ReadAllText($BodyPath, [System.Text.Encoding]::UTF8)
    } else {
        ""
    }
    $errorText = if ($exitCode -eq 0) {
        $null
    } elseif ([string]::IsNullOrWhiteSpace($stderr)) {
        "curl exited $exitCode"
    } else {
        $stderr
    }

    return [pscustomobject]@{
        HttpCode = $httpCode
        Body = $body
        Error = $errorText
    }
}

$checks = @()
$stage = "environment validation"
try {
    $token = $env:GITHUB_TOKEN
    if ([string]::IsNullOrWhiteSpace($token)) {
        $checks += "[FAIL] GITHUB_TOKEN is unavailable"
        Complete-Probe $checks
    }
    if ($token -notmatch '^openshell:resolve:env:v[0-9]+_GITHUB_TOKEN$') {
        $checks += "[FAIL] MXC did not receive a revision-scoped GITHUB_TOKEN placeholder"
        $checks += "[INFO] no network request was attempted"
        Complete-Probe $checks
    }

    $checks += "[PASS] MXC received only a revision-scoped GITHUB_TOKEN placeholder"
    $curlPath = Join-Path $env:SystemRoot "System32\curl.exe"
    if (-not (Test-Path $curlPath)) {
        $checks += "[FAIL] inbox curl.exe is unavailable"
        Complete-Probe $checks
    }
    $caBundle = $env:CURL_CA_BUNDLE
    if ([string]::IsNullOrWhiteSpace($caBundle) -or -not (Test-Path $caBundle)) {
        $checks += "[FAIL] host proxy CA bundle is unavailable"
        Complete-Probe $checks
    }
    $checks += "[PASS] host proxy CA bundle is available to inbox curl"

    $stage = "api.github.com request"
    $github = Invoke-CurlProbe `
        -CurlPath $curlPath `
        -Url "https://api.github.com/user" `
        -BodyPath (Join-Path $OutputDir "github-user-response.json") `
        -CaBundle $caBundle `
        -Token $token
    if ($null -eq $github.Error -and $github.HttpCode -eq "200" -and $github.Body.Contains('"login"')) {
        $checks += "[PASS] GitHub accepted the credential rewritten by the host CONNECT proxy (HTTP 200)"
    } else {
        $errorText = if ($null -eq $github.Error) { "none" } else { $github.Error }
        $checks += "[FAIL] authenticated GitHub request failed (http=$($github.HttpCode), error=$errorText)"
    }

    $stage = "github.com endpoint-mismatch request"
    $mismatch = Invoke-CurlProbe `
        -CurlPath $curlPath `
        -Url "https://github.com/" `
        -BodyPath (Join-Path $OutputDir "credential-mismatch-response.json") `
        -CaBundle $caBundle `
        -Token $token
    if ($null -eq $mismatch.Error -and $mismatch.HttpCode -eq "403" -and $mismatch.Body.Contains("credential_endpoint_mismatch")) {
        $checks += "[PASS] proxy rejected placeholder use outside the GitHub binding (HTTP 403 credential_endpoint_mismatch)"
    } else {
        $errorText = if ($null -eq $mismatch.Error) { "none" } else { $mismatch.Error }
        $checks += "[FAIL] endpoint-mismatch request was not rejected as expected (http=$($mismatch.HttpCode), error=$errorText)"
    }
} catch {
    # Report only the stage and exception type. Exception messages can echo
    # native command arguments, and this probe must never persist credentials.
    $checks += "[FAIL] probe encountered an unexpected error during $stage ($($_.Exception.GetType().Name))"
}

Complete-Probe $checks
