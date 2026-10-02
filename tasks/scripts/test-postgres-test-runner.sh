#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT

# Capture the database passed to the legacy test without running Cargo or
# connecting to a database. An explicit URL also bypasses container startup.
cat >"${TEST_TMP}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${OPENSHELL_REPLAY_TEST_DATABASE_URL:-}" >"${POSTGRES_RUNNER_TEST_RESULT}"
EOF
chmod +x "${TEST_TMP}/cargo"

for legacy_url in "" "postgres://stale.example/other"; do
  PATH="${TEST_TMP}:${PATH}" \
    OPENSHELL_TEST_POSTGRES_URL="postgres://selected.example/disposable" \
    OPENSHELL_REPLAY_TEST_DATABASE_URL="${legacy_url}" \
    POSTGRES_RUNNER_TEST_RESULT="${TEST_TMP}/database-url" \
    bash "${ROOT}/tasks/scripts/run-postgres-tests.sh"

  if [ "$(cat "${TEST_TMP}/database-url")" != "postgres://selected.example/disposable" ]; then
    echo "FAIL: the PostgreSQL test runner did not use the selected database" >&2
    exit 1
  fi
done

echo "PostgreSQL test runner database selection tests passed."
