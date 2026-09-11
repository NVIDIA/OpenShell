#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 DESTINATION CURRENT_DEFAULT LEGACY_DEFAULT" >&2
    exit 2
fi

destination=$1
current_default=$2
legacy_default=$3

for source in "$current_default" "$legacy_default"; do
    # Package-owned defaults must be ordinary files; never follow a symlink.
    if [ -L "$source" ] || [ ! -f "$source" ]; then
        echo "gateway config migration source is not a regular file: $source" >&2
        exit 1
    fi
done

if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
    echo "refusing to replace non-regular gateway config: $destination" >&2
    exit 1
fi

if [ ! -e "$destination" ]; then
    install -Dm 0644 "$current_default" "$destination"
    exit 0
fi

# Replace only the exact config seeded by the schema-v1 RPM. Any edit,
# including whitespace or comments, makes the operator-owned file authoritative.
if ! cmp -s "$legacy_default" "$destination"; then
    exit 0
fi

destination_dir=$(dirname "$destination")
temporary=$(mktemp "$destination_dir/.gateway.toml.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
install -m 0644 "$current_default" "$temporary"
mv -f "$temporary" "$destination"
trap - EXIT HUP INT TERM
