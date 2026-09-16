# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Script,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

$gitCommand = Get-Command git.exe -ErrorAction Stop
$gitRoot = Split-Path -Parent $gitCommand.Source
$bash = $null
# Git can expose cmd/git.exe, mingw64/bin/git.exe, or clangarm64/bin/git.exe.
for ($level = 0; $level -lt 4 -and $gitRoot; $level++) {
    $candidate = Join-Path $gitRoot 'bin\bash.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $bash = $candidate
        break
    }
    $gitRoot = Split-Path -Parent $gitRoot
}
if (-not $bash) {
    throw "Git for Windows bash.exe was not found beside $($gitCommand.Source)"
}

$repoRoot = (& git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw 'Unable to resolve the repository root'
}
$repoPrefix = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$shimDirectory = [IO.Path]::GetFullPath((Join-Path $repoRoot ('.git-bash-shim-' + [guid]::NewGuid().ToString('N'))))
if (-not $shimDirectory.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Git Bash shim directory escaped the repository'
}
$shimCreated = $false
$previousPath = $env:PATH
$previousTmpdir = $env:TMPDIR
$python = $env:UV_PYTHON
if ([string]::IsNullOrWhiteSpace($python)) {
    $worktreePython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $worktreePython -PathType Leaf) {
        $python = $worktreePython
    }
}

try {
    New-Item -ItemType Directory -Path $shimDirectory | Out-Null
    $shimCreated = $true
    if (-not [string]::IsNullOrWhiteSpace($python)) {
        $python = [IO.Path]::GetFullPath($python)
        if ($python -notmatch '^(?<drive>[A-Za-z]):\\(?<tail>.*)$') {
            throw "Python must use an absolute drive path for Git Bash: $python"
        }
        $bashPython = "/$($Matches.drive.ToLowerInvariant())/$($Matches.tail.Replace('\', '/'))"
        if ($bashPython.Contains("'")) {
            throw "Python path cannot contain a single quote: $python"
        }
        $launcher = "#!/usr/bin/env bash`nexec '$bashPython' `"`$@`"`n"
        $utf8WithoutBom = [Text.UTF8Encoding]::new($false)
        foreach ($launcherName in @("python", "python3")) {
            [IO.File]::WriteAllText(
                (Join-Path $shimDirectory $launcherName),
                $launcher,
                $utf8WithoutBom
            )
        }
    }
    $bashTemp = Join-Path $shimDirectory "tmp"
    New-Item -ItemType Directory -Path $bashTemp | Out-Null
    $env:TMPDIR = $bashTemp.Replace("\", "/")
    $env:PATH = "$shimDirectory;$gitRoot\usr\bin;$gitRoot\bin;$env:PATH"
    & $bash $Script @Arguments
    $exitCode = $LASTEXITCODE
} finally {
    $env:PATH = $previousPath
    $env:TMPDIR = $previousTmpdir
    if ($shimCreated -and (Test-Path -LiteralPath $shimDirectory)) {
        $resolvedShim = (Resolve-Path -LiteralPath $shimDirectory).ProviderPath
        if (-not $resolvedShim.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ((Get-Item -LiteralPath $shimDirectory).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing to remove an unexpected Git Bash shim directory'
        }
        Remove-Item -LiteralPath $shimDirectory -Recurse -Force
    }
}

exit $exitCode
