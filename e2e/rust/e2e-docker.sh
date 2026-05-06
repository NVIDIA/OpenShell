#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run a Rust e2e test against a standalone gateway running the bundled Docker
# compute driver. Set OPENSHELL_GATEWAY_ENDPOINT=http://host:port to reuse an
# existing plaintext gateway instead of starting an ephemeral one.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_DOCKER_TEST:-smoke}"
E2E_FEATURES="${OPENSHELL_E2E_DOCKER_FEATURES:-e2e,e2e-docker}"

cargo build -p openshell-cli --features openshell-core/dev-settings

exec "${ROOT}/e2e/with-docker-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features "${E2E_FEATURES}" \
    --test "${E2E_TEST}" \
    -- --nocapture
