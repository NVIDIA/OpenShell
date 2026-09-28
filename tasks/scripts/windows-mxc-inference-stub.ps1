# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int] $Port,

    [Parameter(Mandatory = $true)]
    [string] $RequestLog,

    [Parameter(Mandatory = $true)]
    [string] $ReadyPath,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedBearerToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$utf8 = [System.Text.UTF8Encoding]::new($false)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
[System.IO.File]::WriteAllText($ReadyPath, "$Port`r`n", $utf8)

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new(
                $stream,
                [System.Text.Encoding]::ASCII,
                $false,
                1024,
                $true
            )
            $requestLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($requestLine)) { continue }

            $contentLength = 0
            $authorization = ""
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
                if ($line -match '^Content-Length:\s*(\d+)\s*$') {
                    $contentLength = [int] $Matches[1]
                } elseif ($line -match '^Authorization:\s*(.+)\s*$') {
                    $authorization = $Matches[1]
                }
            }
            if ($contentLength -gt 0) {
                $buffer = New-Object char[] $contentLength
                $read = 0
                while ($read -lt $contentLength) {
                    $count = $reader.Read($buffer, $read, $contentLength - $read)
                    if ($count -le 0) { break }
                    $read += $count
                }
            }

            $parts = $requestLine.Split(' ')
            $path = if ($parts.Count -ge 2) { $parts[1] } else { "/" }
            $authorizationStatus = if ([string]::IsNullOrWhiteSpace($authorization)) {
                "absent"
            } elseif ($authorization -ceq "Bearer $ExpectedBearerToken") {
                "synthetic"
            } else {
                "mismatch"
            }
            [System.IO.File]::AppendAllText(
                $RequestLog,
                "$requestLine authorization=$authorizationStatus`r`n",
                $utf8
            )
            switch ($path) {
                "/api/tags" {
                    $status = "200 OK"
                    $body = '{"models":[{"name":"openshell-ci-mock"}]}'
                }
                "/api/generate" {
                    $status = "200 OK"
                    $body = '{"model":"openshell-ci-mock","response":"Hello from the CI mock.","done":true}'
                }
                "/v1/chat/completions" {
                    if ($authorizationStatus -eq "synthetic") {
                        $status = "200 OK"
                        $body = '{"choices":[{"message":{"role":"assistant","content":"Hello from the CI mock."}}]}'
                    } else {
                        $status = "401 Unauthorized"
                        $body = '{"error":{"message":"invalid mock credential"}}'
                    }
                }
                default {
                    $status = "404 Not Found"
                    $body = '{"error":"not found"}'
                }
            }

            $bodyBytes = $utf8.GetBytes($body)
            $headers = "HTTP/1.1 $status`r`nContent-Type: application/json`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
            $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headers)
            $stream.Write($headerBytes, 0, $headerBytes.Length)
            $stream.Write($bodyBytes, 0, $bodyBytes.Length)
            $stream.Flush()
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
