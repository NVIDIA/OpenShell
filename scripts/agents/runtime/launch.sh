#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# New launchers deliberately use a new entrypoint name. Legacy images with a
# baked assignment cannot silently execute it when passed through --image.
node - "$RUNTIME_DIR/../tooling.json" <<'NODE'
const fs = require("fs");
const metadata = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (metadata.protocol !== 1 ||
    metadata.agent_id !== process.env.OPENSHELL_AGENT_ID ||
    String(metadata.payload_version) !== process.env.OPENSHELL_AGENT_PAYLOAD_VERSION) {
  throw new Error("Tooling image does not match the requested agent/payload version; rebuild it");
}
NODE
exec bash "$RUNTIME_DIR/entrypoint.sh"
