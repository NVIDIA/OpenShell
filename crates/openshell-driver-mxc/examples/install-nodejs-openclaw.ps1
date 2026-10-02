# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# install-nodejs-openclaw.ps1 - fetch a pinned Node.js and the OpenClaw npm
# package, laid out exactly how run-openclaw-forward-test.ps1 expects them.
#
# This is a PREREQUISITE step, not part of the test itself: run it once (or
# with -Force to re-fetch), then pass its printed -NodeExePath /
# -OpenClawInstallDir values straight through to run-openclaw-forward-test.ps1.
# If you already have a working Node.js + OpenClaw install elsewhere, you
# don't need this script at all -- just point run-openclaw-forward-test.ps1 at
# it directly.
#
# What it does:
#   1. Downloads the official Node.js Windows x64 zip build (no installer, no
#      admin rights needed) for a pinned version, verifies its SHA256 against
#      Node.js's published SHASUMS256.txt, and extracts it.
#   2. Uses that Node's bundled npm to install the "openclaw" package from the
#      public npm registry into the same install directory (`npm install
#      openclaw --prefix <dir>`), which lays it out at
#      <dir>\node_modules\openclaw -- exactly what -OpenClawInstallDir expects.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-nodejs-openclaw.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-openclaw-forward-test.ps1 `
#     -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe `
#     -NodeExePath C:\openshell-openclaw-install\node\node.exe `
#     -OpenClawInstallDir C:\openshell-openclaw-install\node_modules\openclaw
#
# Needs outbound internet access to nodejs.org and registry.npmjs.org. If
# your box only reaches the internet through a corporate proxy, set the usual
# HTTP_PROXY/HTTPS_PROXY env vars before running this script -- both
# Invoke-WebRequest and npm respect them.

[CmdletBinding()]
param(
  # Must be a DIRECT CHILD of a drive root (e.g. C:\openshell-openclaw-install,
  # not C:\work\openshell-openclaw-install) for the SAME reason
  # run-openclaw-forward-test.ps1's -ShareDir must be: nothing here actually
  # runs inside the AppContainer, but keeping this path shape consistent
  # avoids surprises if you ever point -ShareDir at this same location.
  [string] $InstallDir = "C:\openshell-openclaw-install",
  # Pinned to the version this package's OpenClaw scenario was validated
  # against (observed working: Node.js v22.22.3). Override if you need a
  # different one, but that combination is untested by this package.
  [string] $NodeVersion = "22.22.3",
  # Pinned to the version this package's OpenClaw scenario was validated
  # against (the package actually exercised by run-openclaw-forward-test.ps1
  # across this repo's live testing). Override (or pass "" for whatever
  # "npm install openclaw" resolves to latest at run time) for ad hoc testing,
  # but that's untested by this package.
  [string] $OpenClawVersion = "2026.7.1",
  # Re-download/re-install even if InstallDir already looks populated.
  [switch] $Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is dramatically faster with the progress bar off.

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }
function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)  { Write-Host "[FAIL] $m" -ForegroundColor Red }

$installDirNorm = $InstallDir.TrimEnd('\','/').Replace('/', '\')
$nodeDir        = Join-Path $installDirNorm "node"
$nodeExe        = Join-Path $nodeDir "node.exe"
$npmCmd         = Join-Path $nodeDir "npm.cmd"
$openClawDir    = Join-Path $installDirNorm "node_modules\openclaw"
$downloadDir    = Join-Path $installDirNorm "_download"

try {
  Step "Node.js v$NodeVersion for win-x64"
  if ((Test-Path $nodeExe) -and -not $Force) {
    $existing = & $nodeExe --version
    Info "already installed at $nodeExe (version $existing) -- pass -Force to re-fetch"
  } else {
    New-Item -ItemType Directory -Force $downloadDir | Out-Null
    $distBase = "https://nodejs.org/dist/v$NodeVersion"
    $zipName  = "node-v$NodeVersion-win-x64.zip"
    $zipPath  = Join-Path $downloadDir $zipName

    Info "downloading $distBase/$zipName"
    Invoke-WebRequest -Uri "$distBase/$zipName" -OutFile $zipPath

    Info "verifying SHA256 against $distBase/SHASUMS256.txt"
    $shasums = Invoke-WebRequest -Uri "$distBase/SHASUMS256.txt" -UseBasicParsing | Select-Object -ExpandProperty Content
    $expectedLine = ($shasums -split "`n") | Where-Object { $_ -match [regex]::Escape($zipName) } | Select-Object -First 1
    if (-not $expectedLine) { throw "no SHASUMS256.txt entry found for $zipName -- refusing to install an unverified download" }
    $expectedHash = ($expectedLine -split '\s+')[0].Trim().ToLowerInvariant()
    $actualHash   = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expectedHash -ne $actualHash) {
      throw "SHA256 mismatch for $zipName`n  expected: $expectedHash`n  actual:   $actualHash`nDeleting the download; do not use it."
    }
    Ok "SHA256 verified: $actualHash"

    Info "extracting to $nodeDir"
    if (Test-Path $nodeDir) { Remove-Item -Recurse -Force $nodeDir }
    $extractStaging = Join-Path $downloadDir "extract"
    if (Test-Path $extractStaging) { Remove-Item -Recurse -Force $extractStaging }
    Expand-Archive -Path $zipPath -DestinationPath $extractStaging -Force
    # The zip's own top-level entry is "node-v<version>-win-x64\..."; flatten
    # that one level so callers get a stable <InstallDir>\node\node.exe path
    # regardless of version.
    $innerDir = Get-ChildItem $extractStaging -Directory | Select-Object -First 1
    if (-not $innerDir) { throw "unexpected zip layout: no top-level directory found after extraction" }
    Move-Item $innerDir.FullName $nodeDir
    Remove-Item -Recurse -Force $extractStaging, $zipPath -ErrorAction SilentlyContinue

    if (-not (Test-Path $nodeExe)) { throw "extraction completed but $nodeExe is missing -- unexpected zip layout" }
    $installedVersion = & $nodeExe --version
    Ok "installed node.exe ($installedVersion) at $nodeExe"
  }

  Step "OpenClaw (npm)"
  if (-not (Test-Path $npmCmd)) { throw "npm.cmd not found next to node.exe at $npmCmd -- Node.js install looks incomplete" }
  # This Node.js install is a standalone zip extraction, not the installer --
  # nothing put it on PATH. npm spawns pre/postinstall scripts (OpenClaw and
  # some of its native-addon deps have them) via cmd.exe, and those scripts
  # invoke bare "node"; without $nodeDir on PATH that fails with "'node' is
  # not recognized...", which in turn makes npm's own cleanup of the
  # half-installed tree fail with a wall of unrelated-looking EPERM rmdir
  # warnings. Prepend $nodeDir to PATH for this call only.
  $env:Path = "$nodeDir;$env:Path"
  if ((Test-Path (Join-Path $openClawDir "openclaw.mjs")) -and -not $Force) {
    Info "already installed at $openClawDir -- pass -Force to re-install"
  } else {
    $pkgSpec = if ($OpenClawVersion) { "openclaw@$OpenClawVersion" } else { "openclaw" }
    Info "npm install $pkgSpec --prefix $installDirNorm"
    # --no-save: this prefix dir isn't a real npm project (no package.json we
    # want npm managing); we just want node_modules\openclaw populated.
    & $npmCmd install $pkgSpec --prefix $installDirNorm --no-save --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
    if (-not (Test-Path (Join-Path $openClawDir "openclaw.mjs"))) {
      throw "npm install succeeded but $openClawDir\openclaw.mjs is missing -- is 'openclaw' really the right package name/layout on the registry you're using?"
    }
    Ok "installed OpenClaw at $openClawDir"
  }

  Remove-Item -Recurse -Force $downloadDir -ErrorAction SilentlyContinue

  Step "Done"
  Write-Host ""
  Write-Host "Pass these to run-openclaw-forward-test.ps1:" -ForegroundColor Yellow
  Write-Host "  -NodeExePath `"$nodeExe`""
  Write-Host "  -OpenClawInstallDir `"$openClawDir`""
  Write-Host ""
  Write-Host "Example:" -ForegroundColor Yellow
  Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File .\run-openclaw-forward-test.ps1 ``"
  Write-Host "    -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe ``"
  Write-Host "    -NodeExePath `"$nodeExe`" ``"
  Write-Host "    -OpenClawInstallDir `"$openClawDir`""
}
catch {
  Bad $_.Exception.Message
  exit 1
}
