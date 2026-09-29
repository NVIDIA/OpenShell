# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

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

    $savedValues = @{}
    foreach ($name in $isolatedValues.Keys) {
        $savedValues[$name] = [System.Environment]::GetEnvironmentVariable(
            $name,
            [System.EnvironmentVariableTarget]::Process
        )
    }

    try {
        foreach ($entry in $isolatedValues.GetEnumerator()) {
            [System.Environment]::SetEnvironmentVariable(
                $entry.Key,
                $entry.Value,
                [System.EnvironmentVariableTarget]::Process
            )
        }
    } catch {
        foreach ($entry in $savedValues.GetEnumerator()) {
            [System.Environment]::SetEnvironmentVariable(
                $entry.Key,
                $entry.Value,
                [System.EnvironmentVariableTarget]::Process
            )
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
        [System.Environment]::SetEnvironmentVariable(
            $entry.Key,
            $entry.Value,
            [System.EnvironmentVariableTarget]::Process
        )
    }
}
