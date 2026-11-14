[CmdletBinding()]
param([switch]$AllowUnsigned, [Parameter(Mandatory)][string]$WxcExecPath)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$manifest = Get-Content -Raw (Join-Path $root 'release-manifest.json') | ConvertFrom-Json
$native = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
$expected = if ($manifest.architecture -eq 'arm64') { 'ARM64' } else { 'AMD64' }
if ($native -ne $expected) { throw "This package requires $expected Windows; this machine reports $native." }
$wxc = (Resolve-Path -LiteralPath $WxcExecPath -ErrorAction Stop).Path
if ($wxc -match '(?i)[\\/]WindowsApps[\\/]') { throw 'Use MXC outside the WindowsApps/MSIX package directory.' }
$probeText = & $wxc --probe
if ($LASTEXITCODE -ne 0) { throw 'MXC capability probe failed.' }
$probe = ($probeText -join "`n") | ConvertFrom-Json
if ($probe.probes.baseContainerSupportsIngressHostLoopbackAllow -ne $true) {
    throw 'This host/MXC does not provide the required native ProcessContainer ingress-loopback capability.'
}
& (Join-Path $PSScriptRoot 'Test-OpenShellPackage.ps1') -AllowUnsigned:$AllowUnsigned
Write-Output "Host probe passed: $native, $wxc"
