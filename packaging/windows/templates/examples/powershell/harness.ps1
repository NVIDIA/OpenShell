#Requires -Version 7.3
[CmdletBinding()]
param([string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'OpenShell\Windows-0.1.8'))
$ErrorActionPreference = 'Stop'
$PSNativeCommandArgumentPassing = 'Standard'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$cli = Join-Path $root 'bin\openshell.exe'
$settings = Get-Content -Raw (Join-Path $StateDirectory 'settings.json') | ConvertFrom-Json
$workspace = (Resolve-Path (Join-Path $StateDirectory 'workspace')).Path
$name = 'win-' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$policy = Join-Path $StateDirectory "$name.yaml"
$template = Get-Content -Raw (Join-Path $root 'policies\harness-local.yaml.template')
$template = $template.Replace('@@WORKSPACE_JSON@@', (ConvertTo-Json -Compress $workspace))
[IO.File]::WriteAllText($policy, $template, [Text.UTF8Encoding]::new($false))
$resultName = "$name-result.txt"
$resultPath = Join-Path $workspace $resultName
$command = @("$env:SystemRoot\System32\cmd.exe",'/d','/c',"echo OpenShell-Windows-harness-ok>$resultName")
$driver = @{mxc=@{command=$command; cwd=$workspace}} | ConvertTo-Json -Compress -Depth 5
$created = $false
try {
    & $cli --gateway-endpoint $settings.endpoint sandbox create --name $name --detach --policy $policy --driver-config-json $driver
    if ($LASTEXITCODE -ne 0) { throw 'Sandbox creation failed.' }
    $created = $true
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        if ((Get-Date) -gt $deadline) { throw 'Workload did not produce its result within 60 seconds.' }
        Start-Sleep -Milliseconds 250
    }
    $output = (Get-Content -Raw -LiteralPath $resultPath).Trim()
    if ($output -ne 'OpenShell-Windows-harness-ok') { throw "Unexpected workload result: $output" }
    Write-Output $output
} finally {
    if ($created) {
        & $cli --gateway-endpoint $settings.endpoint sandbox delete $name
        if ($LASTEXITCODE -ne 0) { Write-Warning "Cleanup failed; delete sandbox $name before stopping the gateway." }
    }
    Remove-Item -LiteralPath $policy -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $resultPath -ErrorAction SilentlyContinue
}
