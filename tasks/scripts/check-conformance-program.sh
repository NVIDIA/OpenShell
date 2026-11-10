#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Check that `openshell-conformance list` names the same tests that nextest
# lists for the conformance crate, so the program runs the whole suite.
# Neither command needs a gateway.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="${root}/tests/suites/conformance/Cargo.toml"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cargo run --quiet --locked --manifest-path "${manifest}" --bin openshell-conformance -- list \
    | awk '{print $1}' | sort > "${work}/program"
# --run-ignored all: the program lists ignored tests too, so nextest must as well.
cargo nextest list --locked --color never --run-ignored all --manifest-path "${manifest}" --message-format oneline \
    | awk '{print $2}' | sort > "${work}/nextest"

if [[ ! -s "${work}/nextest" ]]; then
    echo "error: could not read test names from nextest's list; has its oneline format changed?" >&2
    exit 1
fi
if ! diff -u "${work}/nextest" "${work}/program"; then
    echo "error: openshell-conformance list differs from nextest's list (-nextest +program)" >&2
    exit 1
fi
if [[ ! -s "${work}/program" ]]; then
    echo "error: openshell-conformance lists no tests" >&2
    exit 1
fi
echo "openshell-conformance lists the same $(wc -l < "${work}/program" | tr -d ' ') tests as nextest"
