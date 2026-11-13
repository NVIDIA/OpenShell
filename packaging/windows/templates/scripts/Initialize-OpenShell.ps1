[CmdletBinding()]
param([switch]$AllowUnsigned,
    [Parameter(Mandatory)][string]$WxcExecPath,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'OpenShell\Windows-0.1.8'),
    [ValidateRange(1024,65535)][int]$Port = 17670
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Test-OpenShellHost.ps1') -WxcExecPath $WxcExecPath -AllowUnsigned:$AllowUnsigned
$openssl = (Get-Command openssl -ErrorAction Stop).Source
$state = [IO.Path]::GetFullPath($StateDirectory)
if (Test-Path (Join-Path $state 'settings.json')) { throw "Already initialized: $state. Use Start-OpenShell.ps1 or choose another StateDirectory." }
if (Test-Path (Join-Path $state 'keys\signing.pem')) { throw "A signing key already exists in $state; inspect this partial initialization before retrying." }
New-Item -ItemType Directory -Force $state | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $state /inheritance:r /grant:r "*$($sid):(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the developer state directory.' }
New-Item -ItemType Directory -Force (Join-Path $state 'keys'),(Join-Path $state 'mxc'),(Join-Path $state 'workspace') | Out-Null
$signing = Join-Path $state 'keys\signing.pem'
$public = Join-Path $state 'keys\public.pem'
$kid = Join-Path $state 'keys\kid'
& $openssl genpkey -algorithm ED25519 -out $signing
if ($LASTEXITCODE -ne 0) { throw 'JWT key generation failed.' }
& $openssl pkey -in $signing -pubout -out $public
if ($LASTEXITCODE -ne 0) { throw 'JWT public key generation failed.' }
$identity = 'win-dev-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
[IO.File]::WriteAllText($kid, $identity, [Text.Encoding]::ASCII)
$template = Get-Content -Raw (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\gateway.windows.toml.template')
$values = @{
    SIGNING_KEY=$signing; PUBLIC_KEY=$public; KID=$kid; GATEWAY_ID=$identity
    WXC_EXEC=(Resolve-Path -LiteralPath $WxcExecPath).Path; MXC_STATE=(Join-Path $state 'mxc')
}
foreach ($key in $values.Keys) { $template = $template.Replace("@@$key@@", (ConvertTo-Json -Compress -InputObject ([string]$values[$key]))) }
[IO.File]::WriteAllText((Join-Path $state 'gateway.toml'), $template, [Text.UTF8Encoding]::new($false))
$settings = @{ port=$Port; endpoint="http://127.0.0.1:$Port"; stateDirectory=$state; wxcExecPath=$values.WXC_EXEC }
[IO.File]::WriteAllText((Join-Path $state 'settings.json'), ($settings | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Write-Output "Initialized $state. Start the gateway with scripts\Start-OpenShell.ps1 -StateDirectory '$state'."
