[CmdletBinding()]
param([switch]$AllowUnsigned, [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'OpenShell\Windows-0.1.8'))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$state = (Resolve-Path -LiteralPath $StateDirectory).Path
$settings = Get-Content -Raw (Join-Path $state 'settings.json') | ConvertFrom-Json
& (Join-Path $PSScriptRoot 'Test-OpenShellPackage.ps1') -AllowUnsigned:$AllowUnsigned
$listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
if (@($listeners | Where-Object Port -eq $settings.port).Count) { throw "Port $($settings.port) is already in use." }
$previous = @{}
foreach ($name in @('OPENSHELL_GATEWAY_CONFIG','OPENSHELL_COMPUTE_DRIVER')) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:OPENSHELL_GATEWAY_CONFIG = Join-Path $state 'gateway.toml'
    $env:OPENSHELL_COMPUTE_DRIVER = 'mxc'
    Write-Output "Local developer gateway: $($settings.endpoint). Delete your sandboxes before Ctrl+C. State records are in memory."
    & (Join-Path $root 'bin\openshell-gateway.exe') --bind-address 127.0.0.1 --port $settings.port --health-port 0 --metrics-port 0 --disable-tls --db-url 'sqlite::memory:' --log-level info
    if ($LASTEXITCODE -ne 0) { throw "Gateway exited with code $LASTEXITCODE." }
} finally {
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
