# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

function Set-ProcessEnvironmentVariableExact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [bool] $Exists,
        [AllowNull()]
        [string] $Value
    )

    if (-not $Exists) {
        Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
        return
    }

    if ($Value.Length -eq 0) {
        # Windows PowerShell 5.1 maps an empty value passed through
        # Environment.SetEnvironmentVariable to deletion. Call Win32 directly
        # so an inherited empty entry remains distinguishable from absence.
        if (-not ("OpenShellMxcProcessEnvironmentNative" -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class OpenShellMxcProcessEnvironmentNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetEnvironmentVariable(string name, string value);
}
'@
        }
        if (-not [OpenShellMxcProcessEnvironmentNative]::SetEnvironmentVariable($Name, [string]::Empty)) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "failed to restore empty process environment variable '$Name' (Win32 error $errorCode)"
        }
        return
    }

    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
}

function Push-OpenShellMxcE2eEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $StageDir
    )

    $isolatedValues = [ordered]@{
        APPDATA                    = Join-Path $StageDir "appdata"
        LOCALAPPDATA               = Join-Path $StageDir "localappdata"
        XDG_CONFIG_HOME            = Join-Path $StageDir "xdg-config"
        XDG_STATE_HOME             = Join-Path $StageDir "xdg-state"
        XDG_DATA_HOME              = Join-Path $StageDir "xdg-data"
        OPENSHELL_GATEWAY          = $null
        OPENSHELL_GATEWAY_ENDPOINT = $null
        OPENSHELL_GATEWAY_INSECURE = $null
        OPENSHELL_GATEWAY_CONFIG   = $null
        OPENSHELL_GATEWAY_NAME     = $null
    }

    New-Item -ItemType Directory -Force -Path @(
        $isolatedValues.APPDATA
        $isolatedValues.LOCALAPPDATA
        $isolatedValues.XDG_CONFIG_HOME
        $isolatedValues.XDG_STATE_HOME
        $isolatedValues.XDG_DATA_HOME
    ) | Out-Null

    $processEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $savedValues = @{}
    foreach ($name in $isolatedValues.Keys) {
        $exists = $processEnvironment.Contains($name)
        $savedValues[$name] = [pscustomobject]@{
            Exists = $exists
            Value = if ($exists) { [string] $processEnvironment[$name] } else { $null }
        }
    }

    try {
        foreach ($entry in $isolatedValues.GetEnumerator()) {
            if ($null -eq $entry.Value) {
                Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue
            } else {
                [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
            }
        }
    } catch {
        foreach ($entry in $savedValues.GetEnumerator()) {
            Set-ProcessEnvironmentVariableExact `
                -Name $entry.Key `
                -Exists $entry.Value.Exists `
                -Value $entry.Value.Value
        }
        throw
    }

    return [pscustomobject]@{ Values = $savedValues }
}

function Pop-OpenShellMxcE2eEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject] $Snapshot
    )

    foreach ($entry in $Snapshot.Values.GetEnumerator()) {
        Set-ProcessEnvironmentVariableExact `
            -Name $entry.Key `
            -Exists $entry.Value.Exists `
            -Value $entry.Value.Value
    }
}
