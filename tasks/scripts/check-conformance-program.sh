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
# unsupported.yaml must pass the program's own checks (known tests, https
# issues, no duplicates) for every environment it names, and name only
# environments that exist.
unsupported_file="${OPENSHELL_UNSUPPORTED_FILE:-${root}/tests/suites/conformance/unsupported.yaml}"
# Environments are the conformance rows of e2e-suites.yml (<environment>/<installer>)
# and the host lanes; a misspelled name would never apply.
known="$(yq '.jobs.select.steps[] | select(.id == "rows") | .run' "${root}/.github/workflows/e2e-suites.yml" \
    | sed -n "/rows='\[/,/^ *\]'/p" | sed "1s/.*rows='//; \$s/'.*//" \
    | yq '.[] | select(.family == "conformance") | .environment + "/" + .installer')
docker
podman
kubernetes
vm"
while IFS= read -r environment; do
    if ! grep -qxF "${environment}" <<< "${known}"; then
        echo "error: unsupported.yaml: unknown environment ${environment}; use a conformance row of e2e-suites.yml (<environment>/<installer>), docker, podman, kubernetes or vm" >&2
        exit 1
    fi
    OPENSHELL_TEST_UNSUPPORTED="$("${root}/tasks/scripts/conformance-unsupported.sh" "${environment}")" \
        cargo run --quiet --locked --manifest-path "${manifest}" --bin openshell-conformance -- list > /dev/null
done < <(yq -r '.[].environments[]' "${unsupported_file}" | sort -u)
echo "openshell-conformance lists the same $(wc -l < "${work}/program" | tr -d ' ') tests as nextest"
