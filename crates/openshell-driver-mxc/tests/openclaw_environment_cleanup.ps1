# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

param([string]$RunnerPath, [string]$TestDirectory)
$ErrorActionPreference = 'Stop'

# Execute the actual runner's override scope, not a copy of its cleanup logic.
$tokens = $null
$parseErrors = $null
$source = [System.IO.File]::ReadAllText($RunnerPath)
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Runner must parse without errors' }
$scope = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
    $node.Finally -and $node.Finally.Extent.Text.Contains('$savedOpenClawConfigPath')
}, $true)
if (!$scope) { throw 'OpenClaw environment restoration needs a finally scope' }
$save = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -eq '$savedOpenClawConfigPath'
}, $true)
$exercise = [scriptblock]::Create($source.Substring($save.Extent.StartOffset, $scope.Extent.EndOffset - $save.Extent.StartOffset))

function Step { param($Message) }
function Info { param($Message) }
function Ok { param($Message) }
function Bad { param($Message) throw $Message }
$ShareDir = $TestDirectory
$resultDir = $TestDirectory
$expectedState = Join-Path $ShareDir 'home\.openclaw'
$expectedConfig = Join-Path $expectedState 'openclaw.json'
$healthArgs = @()
$proof = '[egress-proof] {"proxyConfigured":true,"allowedViaProxy":{"connected":true},"deniedViaProxy":{"connected":false},"directInternetBypass":{"connected":false},"unrelatedHostLoopback":{"connected":true}}'
[System.IO.File]::WriteAllText((Join-Path $ShareDir 'openclaw-capture.log'), $proof)
$originalConfig = $env:OPENCLAW_CONFIG_PATH
$originalState = $env:OPENCLAW_STATE_DIR
$cases = 0
try {
    foreach ($initial in @($null, 'original-value')) {
        foreach ($injectFailure in @($false, $true)) {
            $env:OPENCLAW_CONFIG_PATH = $initial
            $env:OPENCLAW_STATE_DIR = $initial
            $passed = $false
            $NodeExePath = {
                if ($env:OPENCLAW_CONFIG_PATH -ne $expectedConfig -or $env:OPENCLAW_STATE_DIR -ne $expectedState) {
                    throw 'Client did not receive isolated OpenClaw paths'
                }
                if ($injectFailure) { throw 'injected-client-failure' }
                '{"ok":true}'
            }
            $caught = $false
            try { . $exercise } catch {
                if (!$injectFailure -or $_.Exception.Message -ne 'injected-client-failure') { throw }
                $caught = $true
            }
            if ($caught -ne $injectFailure) { throw 'Unexpected execution outcome' }
            if (!$injectFailure -and !$passed) { throw 'Successful health path did not pass' }
            if ($env:OPENCLAW_CONFIG_PATH -cne $initial -or $env:OPENCLAW_STATE_DIR -cne $initial) {
                throw 'Environment was not restored after the client scope'
            }
            $cases++
        }
    }
} finally {
    $env:OPENCLAW_CONFIG_PATH = $originalConfig
    $env:OPENCLAW_STATE_DIR = $originalState
}
Write-Output "PASS: $cases environment restoration cases"
