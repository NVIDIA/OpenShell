#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against a standalone gateway running the bundled Podman
# compute driver. Set OPENSHELL_GATEWAY_ENDPOINT=http://host:port to reuse an
# existing plaintext gateway instead of starting an ephemeral one.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo build -p openshell-cli --features openshell-core/dev-settings

exec "${ROOT}/e2e/with-podman-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features e2e \
    -- --nocapture
