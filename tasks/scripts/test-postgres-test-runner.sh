#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT

# Capture the database passed to the legacy test and Cargo's arguments without
# running Cargo or connecting to a database. An explicit URL also bypasses
# container startup.
cat >"${TEST_TMP}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${OPENSHELL_REPLAY_TEST_DATABASE_URL:-}" >"${POSTGRES_RUNNER_TEST_RESULT}"
printf '%s\n' "$@" >"${POSTGRES_RUNNER_TEST_ARGS}"
EOF
chmod +x "${TEST_TMP}/cargo"

# Run the runner with extra NAME=value environment settings.
run_runner() {
  rm -f "${TEST_TMP}/cargo-args"
  PATH="${TEST_TMP}:${PATH}" \
    OPENSHELL_TEST_POSTGRES_URL="postgres://selected.example/disposable" \
    POSTGRES_RUNNER_TEST_RESULT="${TEST_TMP}/database-url" \
    POSTGRES_RUNNER_TEST_ARGS="${TEST_TMP}/cargo-args" \
    env "$@" bash "${ROOT}/tasks/scripts/run-postgres-tests.sh"
}

expect_filter() {
  if ! grep -qxF "test(/(^|::)$1/)" "${TEST_TMP}/cargo-args"; then
    echo "FAIL: the PostgreSQL test runner did not filter on the $1 prefix" >&2
    exit 1
  fi
}

for legacy_url in "" "postgres://stale.example/other"; do
  run_runner OPENSHELL_REPLAY_TEST_DATABASE_URL="${legacy_url}" OPENSHELL_TEST_POSTGRES_PREFIX=

  if [ "$(cat "${TEST_TMP}/database-url")" != "postgres://selected.example/disposable" ]; then
    echo "FAIL: the PostgreSQL test runner did not use the selected database" >&2
    exit 1
  fi
  expect_filter postgres_
done

run_runner OPENSHELL_TEST_POSTGRES_PREFIX=bench_postgres_
expect_filter bench_postgres_

# The prefix lands in the nextest filterset, so a bad one must stop before Cargo.
if run_runner OPENSHELL_TEST_POSTGRES_PREFIX='x)|all(' 2>/dev/null || [ -e "${TEST_TMP}/cargo-args" ]; then
  echo "FAIL: the PostgreSQL test runner accepted an invalid test-name prefix" >&2
  exit 1
fi

echo "PostgreSQL test runner database and prefix selection tests passed."
