#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the PostgreSQL-backed openshell-server tests: #[ignore] tests whose names
# start with `postgres_`. Point OPENSHELL_TEST_POSTGRES_URL at a disposable
# database, or leave it unset to start a throwaway PostgreSQL container with
# the local container engine (Docker or Podman). Never point it at a database
# that a running gateway uses: the tests take fleet-wide advisory locks.
#
# Extra arguments are passed to cargo nextest. Use test-name filters to run a
# subset, for example `postgres_get_resource_versions`; a second -E filterset
# would widen the selection instead of narrowing it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# Same pinned image as the Kubernetes e2e fixture (e2e/kubernetes/postgres-fixture.yaml).
POSTGRES_IMAGE="${OPENSHELL_TEST_POSTGRES_IMAGE:-mirror.gcr.io/library/postgres:17.10-alpine3.23@sha256:979c4379dd698aba0b890599a6104e082035f98ef31d9b9291ec22f2b13059ca}"
CONTAINER_NAME=""

cleanup() {
  if [ -n "${CONTAINER_NAME}" ]; then
    ce rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

start_postgres() {
  local password port ready=0
  # shellcheck source=tasks/scripts/container-engine.sh
  source "${ROOT}/tasks/scripts/container-engine.sh"

  password="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  CONTAINER_NAME="openshell-test-postgres-$$"
  echo "Starting disposable PostgreSQL (${POSTGRES_IMAGE})..."
  # No --rm: the EXIT trap removes the container, and keeping it until then
  # preserves its logs when PostgreSQL fails to start.
  ce run -d --name "${CONTAINER_NAME}" \
    -e POSTGRES_USER=openshell \
    -e POSTGRES_PASSWORD="${password}" \
    -e POSTGRES_DB=openshell \
    -p 127.0.0.1::5432 \
    "${POSTGRES_IMAGE}" >/dev/null

  # The image's init phase runs a socket-only server, so a TCP probe succeeds
  # only once the final server accepts connections.
  for _ in $(seq 1 60); do
    if ce exec "${CONTAINER_NAME}" pg_isready -h 127.0.0.1 -U openshell -d openshell >/dev/null 2>&1; then
      ready=1
      break
    fi
    if [ "$(ce inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null)" != "true" ]; then
      break
    fi
    sleep 1
  done
  if [ "${ready}" != "1" ]; then
    echo "ERROR: PostgreSQL did not become ready within 60s or its container exited" >&2
    ce logs "${CONTAINER_NAME}" >&2 || true
    exit 1
  fi

  port="$(ce port "${CONTAINER_NAME}" 5432/tcp | head -n1 | awk -F: '{print $NF}')"
  echo "PostgreSQL is ready on 127.0.0.1:${port} (container ${CONTAINER_NAME})"
  export OPENSHELL_TEST_POSTGRES_URL="postgres://openshell:${password}@127.0.0.1:${port}/openshell"
}

if [ -z "${OPENSHELL_TEST_POSTGRES_URL:-}" ]; then
  start_postgres
fi

# The mutation-replay test predates OPENSHELL_TEST_POSTGRES_URL.
export OPENSHELL_REPLAY_TEST_DATABASE_URL="${OPENSHELL_REPLAY_TEST_DATABASE_URL:-${OPENSHELL_TEST_POSTGRES_URL}}"
export OPENSHELL_TELEMETRY_ENABLED=false

# Advisory locks are database-wide, so run the tests one at a time.
cargo nextest run -p openshell-server --features test-support \
  --run-ignored only --test-threads 1 \
  -E 'test(/(^|::)postgres_/)' "$@"
