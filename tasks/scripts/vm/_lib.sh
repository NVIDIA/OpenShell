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
