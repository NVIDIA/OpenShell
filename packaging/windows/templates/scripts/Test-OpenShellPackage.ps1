[CmdletBinding()]
param([switch]$AllowUnsigned)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$manifest = Get-Content -Raw -LiteralPath (Join-Path $root 'release-manifest.json') | ConvertFrom-Json
if ($manifest.architecture -notin @('arm64','x64')) { throw 'Invalid package architecture' }
$seen = @{}
foreach ($file in $manifest.files) {
    $path = [IO.Path]::GetFullPath((Join-Path $root $file.path))
    if (-not $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path leaves package' }
    if ($seen.ContainsKey($path)) { throw 'Duplicate manifest entry' }
    $seen[$path] = $true
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing package file: $($file.path)" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw "Package hash mismatch: $($file.path)" }
}
$machine = if ($manifest.architecture -eq 'arm64') { 0xAA64 } else { 0x8664 }
foreach ($name in @('openshell.exe','openshell-gateway.exe','openshell-supervisor.exe','openshell-windows-sandbox.exe','libz3.dll')) {
    $path = Join-Path $root "bin\$name"
    if (-not $seen.ContainsKey([IO.Path]::GetFullPath($path))) { throw "Executable is not in manifest: $name" }
    $bytes = [IO.File]::ReadAllBytes($path)
    $offset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ([BitConverter]::ToUInt16($bytes, $offset + 4) -ne $machine) { throw "Wrong PE architecture: $name" }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid') {
        if (-not $AllowUnsigned -or $signature.Status -ne 'NotSigned') { throw "Invalid or absent Authenticode signature: $name ($($signature.Status))" }
        Write-Warning "Unsigned candidate: $name. This is not a release-ready package."
    } elseif (-not $signature.TimeStamperCertificate) { throw "Missing Authenticode timestamp: $name" }
}
foreach ($name in @('openshell.exe','openshell-gateway.exe','openshell-supervisor.exe','openshell-windows-sandbox.exe')) {
    & (Join-Path $root "bin\$name") --version
    if ($LASTEXITCODE -ne 0) { throw "Executable launch failed: $name; check the matching Visual C++ runtime and libz3.dll." }
}
Write-Output "Package hashes, signatures, and $($manifest.architecture) executable launches checked. Source: $($manifest.source.commit)"
Write-Output 'Verify the ZIP GitHub attestation separately before trusting this manifest.'
