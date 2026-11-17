# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Read PE imports without requiring dumpbin or a developer environment on the
# runtime host. Both supported Windows architectures use PE32+ images.
function Get-WindowsImageDependencies([string] $Path) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
    $stream = $reader.BaseStream
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw "Invalid PE image: $Path" }
        $stream.Position = 0x3c
        $pe = $reader.ReadUInt32()
        if ($pe -gt $stream.Length - 24) { throw "Invalid PE offset: $Path" }
        $stream.Position = $pe
        if ($reader.ReadUInt32() -ne 0x4550) { throw "Invalid PE signature: $Path" }
        $machine = $reader.ReadUInt16()
        $sectionCount = $reader.ReadUInt16()
        $stream.Position = $pe + 20
        $optionalSize = $reader.ReadUInt16()
        $optional = $pe + 24
        if ($optionalSize -lt 128 -or $optional + $optionalSize + 40 * $sectionCount -gt $stream.Length) { throw "Invalid PE headers: $Path" }
        $stream.Position = $optional
        if ($reader.ReadUInt16() -ne 0x20b) { throw "Expected PE32+ image: $Path" }
        $stream.Position = $optional + 108
        $directoryCount = $reader.ReadUInt32()
        if ($directoryCount -lt 2 -or 112 + 8 * $directoryCount -gt $optionalSize) { throw "Invalid PE directories: $Path" }
        $sections = @()
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $stream.Position = $optional + $optionalSize + 40 * $i + 8
            $sections += [pscustomobject]@{
                VirtualSize = $reader.ReadUInt32(); VirtualAddress = $reader.ReadUInt32()
                RawSize = $reader.ReadUInt32(); RawOffset = $reader.ReadUInt32()
            }
        }
        function Resolve-ImageRva([uint32] $Rva) {
            foreach ($section in $sections) {
                $relative = [long]$Rva - $section.VirtualAddress
                if ($relative -ge 0 -and $relative -lt $section.RawSize) {
                    $offset = [long]$section.RawOffset + $relative
                    if ($offset -lt $stream.Length) { return $offset }
                }
            }
            throw "Invalid PE RVA in $Path"
        }
        $dependencies = @()
        foreach ($index in @(1, 13)) {
            if ($directoryCount -le $index) { continue }
            $stream.Position = $optional + 112 + 8 * $index
            $rva = $reader.ReadUInt32()
            $size = $reader.ReadUInt32()
            if ($rva -eq 0) { continue }
            $descriptorSize = if ($index -eq 1) { 20 } else { 32 }
            $directory = Resolve-ImageRva $rva
            $terminated = $false
            for ($position = $directory; $position + $descriptorSize -le [Math]::Min($stream.Length, $directory + $size); $position += $descriptorSize) {
                $stream.Position = $position
                $fields = @(for ($j = 0; $j -lt $descriptorSize / 4; $j++) { $reader.ReadUInt32() })
                if (@($fields | Where-Object { $_ -ne 0 }).Count -eq 0) { $terminated = $true; break }
                # Modern delay-import descriptors store RVAs (attribute bit 0).
                if ($index -eq 13 -and ($fields[0] -band 1) -eq 0) { throw "Unsupported delay-import addressing: $Path" }
                $nameRva = if ($index -eq 1) { $fields[3] } else { $fields[1] }
                $stream.Position = Resolve-ImageRva $nameRva
                $name = [Text.StringBuilder]::new()
                do {
                    if ($stream.Position -ge $stream.Length -or $name.Length -gt 260) { throw "Invalid PE import name: $Path" }
                    $byte = $reader.ReadByte()
                    if ($byte) { [void]$name.Append([char]$byte) }
                } while ($byte)
                $dependencies += $name.ToString()
            }
            if (-not $terminated) { throw "Unterminated PE import directory: $Path" }
        }
        return [pscustomobject]@{ Machine = $machine; Dependencies = @($dependencies | Sort-Object -Unique) }
    } finally { $reader.Dispose() }
}

function Assert-StaticWindowsRuntime([string] $Path, [string] $RustTarget) {
    $image = Get-WindowsImageDependencies $Path
    $expected = switch ($RustTarget) {
        'aarch64-pc-windows-msvc' { 0xaa64 }
        'x86_64-pc-windows-msvc' { 0x8664 }
        default { throw "Unsupported Windows target: $RustTarget" }
    }
    if ($image.Machine -ne $expected) { throw "PE architecture does not match ${RustTarget}: $Path" }
    $dynamic = @($image.Dependencies | Where-Object {
        $_ -match '^(libz3|z3|vcruntime\d+[^.]*|msvcp\d+[^.]*|msvcr\d+[^.]*|concrt\d+[^.]*|ucrtbased?|api-ms-win-crt-[^.]+)\.dll$'
    })
    if ($dynamic.Count) { throw "Dynamic Z3/CRT dependency in ${Path}: $($dynamic -join ', ')" }
    Write-Host "==> Static Z3/CRT and PE architecture verified: $Path"
}
