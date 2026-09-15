#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Backend names are permitted only in the adapter implementation and its manifest.
# Word boundaries avoid matching identifiers such as String::from.
if rg -n '\b(aws_lc_rs|ring)::|\bcrypto::aws_lc::|tls-aws-lc|tls-rustls-aws-lc-rs|"aws[-_]lc[-_]rs"|^aws-lc-rs\s*=' \
    crates examples e2e --glob '*.rs' --glob Cargo.toml \
    --glob '!**/openshell-crypto/**'; then
    echo 'Direct backend use must live in openshell-crypto.' >&2
    exit 1
else
    result=$?
    if [[ "$result" != 1 ]]; then
        exit "$result"
    fi
fi
