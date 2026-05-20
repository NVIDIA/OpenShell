#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for VM runtime build scripts.
# Source this file from other scripts:
#   source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

# ── Root directory ──────────────────────────────────────────────────────

vm_lib_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd
}

# ── Platform detection ──────────────────────────────────────────────────

# Detect the current platform and echo one of:
#   darwin-aarch64, linux-aarch64, linux-x86_64
# Exits with error on unsupported platforms.
detect_platform() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64)   echo "darwin-aarch64" ;;
        Linux-aarch64)  echo "linux-aarch64" ;;
        Linux-x86_64)   echo "linux-x86_64" ;;
        *)
            echo "Error: Unsupported platform: $(uname -s)-$(uname -m)" >&2
            echo "Supported: macOS ARM64, Linux ARM64, Linux x86_64" >&2
            return 1
            ;;
    esac
}

# ── Runtime dependency downloads ────────────────────────────────────────

# Download a Linux guest umoci binary for the requested architecture.
# Usage: download_umoci_binary <output> <version> <guest_arch>
download_umoci_binary() {
    local output="$1"
    local version="$2"
    local guest_arch="$3"
    local suffix

    case "$guest_arch" in
        arm64|aarch64) suffix="arm64" ;;
        amd64|x86_64)  suffix="amd64" ;;
        *)
            echo "Error: Unsupported guest architecture for umoci: ${guest_arch}" >&2
            return 1
            ;;
    esac

    local base_url="https://github.com/opencontainers/umoci/releases/download/${version}"
    local candidates=("umoci.linux.${suffix}" "umoci.${suffix}")
    local error_log last_error asset
    error_log="$(mktemp)"
    last_error=""

    echo "    Downloading umoci ${version} for linux/${suffix}..."
    for asset in "${candidates[@]}"; do
        if curl -fsSL -o "$output" "${base_url}/${asset}" 2>"$error_log"; then
            chmod +x "$output"
            rm -f "$error_log"
            return 0
        fi
        last_error="$(cat "$error_log")"
        rm -f "$output"
    done

    rm -f "$error_log"
    echo "Error: failed to download umoci ${version} for linux/${suffix}" >&2
    if [ -n "$last_error" ]; then
        echo "$last_error" >&2
    fi
    return 1
}

# Map a VM runtime platform to the Linux guest umoci architecture.
# Usage: umoci_guest_arch_for_platform <platform>
umoci_guest_arch_for_platform() {
    local platform="$1"

    case "$platform" in
        linux-aarch64|darwin-aarch64) echo "arm64" ;;
        linux-x86_64)                 echo "amd64" ;;
        *)
            echo "Error: Unsupported platform for umoci guest binary: ${platform}" >&2
            return 1
            ;;
    esac
}

# Ensure an extracted runtime directory contains the guest umoci binary.
# Usage: ensure_umoci_for_platform <runtime_dir> <platform> <version>
ensure_umoci_for_platform() {
    local runtime_dir="$1"
    local platform="$2"
    local version="$3"

    if [ -f "${runtime_dir}/umoci" ]; then
        return 0
    fi

    local guest_arch
    guest_arch="$(umoci_guest_arch_for_platform "$platform")"
    echo "    Runtime tarball has no umoci"
    download_umoci_binary "${runtime_dir}/umoci" "$version" "$guest_arch"
}

# ── Compression helpers ─────────────────────────────────────────────────

# Compress a single file with zstd level 19, reporting sizes.
# Usage: compress_file <input> <output>
compress_file() {
    local input="$1"
    local output="$2"
    local name
    name="$(basename "$input")"
    local original_size
    original_size="$(du -h "$input" | cut -f1)"

    zstd -19 -f -q -T0 -o "$output" "$input"
    chmod 644 "$output"

    local compressed_size
    compressed_size="$(du -h "$output" | cut -f1)"
    echo "    ${name}: ${original_size} -> ${compressed_size}"
}

# Compress all files in a directory (skipping provenance.json) into an
# output directory, appending .zst to each filename.
# Usage: compress_dir <source_dir> <output_dir>
compress_dir() {
    local source_dir="$1"
    local output_dir="$2"

    echo "==> Compressing with zstd (level 19)..."
    for file in "$source_dir"/*; do
        [ -f "$file" ] || continue
        local name
        name="$(basename "$file")"
        # Skip metadata files — not embedded
        if [ "$name" = "provenance.json" ]; then
            cp "$file" "${output_dir}/"
            continue
        fi
        compress_file "$file" "${output_dir}/${name}.zst"
    done
}
