param([ValidateSet('arm64','x64')][string]$Architecture)
$ErrorActionPreference = 'Stop'
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$source = (Get-Location).Path
$env:CARGO_TARGET_DIR = Join-Path $source 'target'
$env:CARGO_INCREMENTAL = '0'
$env:OPENSHELL_WINDOWS_BUILD_JOBS = '4'
$env:OPENSHELL_WINDOWS_STATIC_RUNTIME = '1'
$env:OPENSHELL_WINDOWS_Z3_SOURCE = '1'
$env:OPENSHELL_IMAGE_TAG = '0.1.9'
$env:MISE_TRUSTED_CONFIG_PATHS = $source
$env:CARGO_HOME = Join-Path $env:USERPROFILE '.cargo'
$pairs = @(
    @($env:GITHUB_WORKSPACE, '/build'),
    @($source, '/src/openshell'),
    @($env:CARGO_HOME, '/cargo'),
    @($env:RUSTUP_HOME, '/rustup'),
    @($env:USERPROFILE, '/build-user')
)
$maps = @()
$fso = New-Object -ComObject Scripting.FileSystemObject
foreach ($pair in $pairs) {
    $prefixes = @($pair[0])
    if (Test-Path $pair[0]) { $prefixes += $fso.GetFolder($pair[0]).ShortPath }
    foreach ($prefix in $prefixes) {
        foreach ($variant in @($prefix, $prefix.Replace('\','/'), $prefix.ToLowerInvariant(), $prefix.Replace('\','/').ToLowerInvariant())) {
            $maps += @{ Prefix=$variant; Replacement=$pair[1] }
            Write-Output "::add-mask::$variant"
        }
    }
}
# Environment flags override target rustflags, including windows-static.toml.
$rustFlags = @('-C', 'target-feature=+crt-static') + @($maps | ForEach-Object { "--remap-path-prefix=$($_.Prefix)=$($_.Replacement)" })
$env:CARGO_ENCODED_RUSTFLAGS = $rustFlags -join [char]31
# The pinned prebuilt Z3 libraries embed their producer's absolute source paths.
# Use the repository's checksum-verified source mode and remap C++ __FILE__ too.
$env:CXXFLAGS = '/experimental:deterministic ' + (($maps | ForEach-Object { "/pathmap:$($_.Prefix)=$($_.Replacement)" }) -join ' ')
"CXXFLAGS=$env:CXXFLAGS" >> $env:GITHUB_ENV
$env:AWS_LC_SYS_CFLAGS = if ($Architecture -eq 'arm64') {
    ($maps | ForEach-Object { "/clang:-ffile-prefix-map=$($_.Prefix)=$($_.Replacement)" }) -join ' '
} else {
    '/experimental:deterministic ' + (($maps | ForEach-Object { "/pathmap:$($_.Prefix)=$($_.Replacement)" }) -join ' ')
}
# Match the existing release version-stamping convention without inventing a tag.
$cargo = Get-Content -Raw Cargo.toml
if ($cargo -notmatch '(?m)^version = "0\.0\.0"\r?$') { throw 'Unexpected workspace version' }
[IO.File]::WriteAllText((Join-Path $source 'Cargo.toml'), ($cargo -replace '(?m)^version = "0\.0\.0"\r?$', 'version = "0.1.9"'))
# Git-derived development versions must not override the stamped package version.
$env:GIT_DIR = Join-Path $env:RUNNER_TEMP 'absent-release-git'
& mise run --skip-tools "windows:build:$Architecture"
if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
& mise run --skip-tools "windows:build:mxc-fixtures:$Architecture"
if ($LASTEXITCODE -ne 0) { throw 'Validation fixture build failed' }
$out = Join-Path $env:GITHUB_WORKSPACE "native-$Architecture"
New-Item -ItemType Directory -Force $out | Out-Null
$files = @()
function Assert-Sanitized([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    foreach ($encoding in @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode)) {
        $text = $encoding.GetString($bytes)
        foreach ($mapping in $maps) {
            if ($text.IndexOf($mapping.Prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "Build path remains in $([IO.Path]::GetFileName($Path))"
            }
        }
    }
}
. (Join-Path $source 'tasks/scripts/windows-runtime.ps1')
if (Test-Path (Join-Path $env:CARGO_TARGET_DIR "$target/release/libz3.dll")) { throw 'Static release unexpectedly contains libz3.dll' }
foreach ($name in @('openshell.exe','openshell-gateway.exe','openshell-supervisor.exe','openshell-windows-sandbox.exe')) {
    $path = Join-Path $env:CARGO_TARGET_DIR "$target/release/$name"
    Assert-StaticWindowsRuntime $path $target
    Assert-Sanitized $path
    Copy-Item $path $out
    if ($name.EndsWith('.exe')) {
        $version = & $path --version
        if ($LASTEXITCODE -ne 0 -or "$version" -notmatch '0\.1\.9') { throw "Executable version/launch failed: $name" }
    }
    $signature = Get-AuthenticodeSignature $path
    $files += @{ file=$name; sha256=(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(); signature=$signature.Status.ToString(); dependencies=@((Get-WindowsImageDependencies $path).Dependencies); staticRuntimeAudit='passed' }
}
@{architecture=$Architecture; source=$env:SOURCE_SHA; rust=(& rustc --version); runner=$env:RUNNER_ARCH; version='0.1.9'; launchChecks='passed'; runtime='static-crt-and-z3'; z3BuildMode='pinned-source-with-path-remapping'; z3Pin=(Get-Content -Raw (Join-Path $source 'tasks/windows-z3.json') | ConvertFrom-Json); files=$files} | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'build-record.json')
$validation = Join-Path $env:GITHUB_WORKSPACE "validation-$Architecture"
New-Item -ItemType Directory -Force $validation | Out-Null
$fixture = Join-Path $env:CARGO_TARGET_DIR "$target/release/examples/mxc-forwarding-agent.exe"
Assert-Sanitized $fixture
Copy-Item $fixture $validation
Copy-Item -Recurse (Join-Path $source 'crates/openshell-driver-mxc/examples') (Join-Path $validation 'examples')
# Never upload compiler output, local runtime state, PDBs, or generated keys.
