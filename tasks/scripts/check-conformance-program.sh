#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Check that `openshell-conformance list` names the same tests that nextest
# lists for the conformance crate, so the program runs the whole suite.
# Also check harness settings and unsupported.yaml across all suite workspaces.
# Listing tests does not need a gateway.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
suites="${root}/tests/suites"
conformance="${suites}/conformance/Cargo.toml"
manifests=("${conformance}" "${suites}/features/Cargo.toml" "${suites}"/drivers/*/Cargo.toml)
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
unset OPENSHELL_TEST_UNSUPPORTED

cargo run --quiet --locked --manifest-path "${conformance}" --bin openshell-conformance -- list \
    | awk '{print $1}' | sort > "${work}/program"
# --run-ignored all: the program lists ignored tests too, so nextest must as well.
cargo nextest list --locked --color never --run-ignored all --manifest-path "${conformance}" --message-format oneline \
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

# Cargo metadata includes auto-discovered integration targets, but not their
# harness settings. Check the manifest for the explicit opt-out.
# The conformance binary registers tests from its library, not its own crate.
printf '%s\n' conformance > "${work}/crates"
for manifest in "${manifests[@]}"; do
    # shellcheck disable=SC2016 # $manifest inside the yq expression is a yq variable.
    cargo metadata --locked --no-deps --format-version 1 --manifest-path "${manifest}" \
        | yq -p=json -r '.packages[] | select(.dependencies[] | .name == "openshell-testkit")
            | .manifest_path as $manifest | .targets[]
            | select(.test and (.kind[0] == "test" or .kind[0] == "bin"))
            | [$manifest, .kind[0], .name] | @tsv' > "${work}/targets"
    while IFS=$'\t' read -r package kind target; do
        harnessless="$(target_name="${target}" target_kind="${kind}" yq -p=toml -o=yaml -r \
            '.[strenv(target_kind)][] | select(.name == strenv(target_name) and .harness == false) | .name' "${package}")"
        if [[ -z "${harnessless}" ]]; then
            echo "error: ${package}: ${target} needs an explicit [[${kind}]] with harness = false" >&2
            exit 1
        fi
        if [[ "${kind}" == test ]]; then
            printf '%s\n' "${target//-/_}" >> "${work}/crates"
        fi
    done < "${work}/targets"
done
duplicates="$(sort "${work}/crates" | uniq -d)"
if [[ -n "${duplicates}" ]]; then
    echo "error: testkit test target crate names must be unique: ${duplicates}" >&2
    exit 1
fi

unsupported_file="${OPENSHELL_UNSUPPORTED_FILE:-${suites}/unsupported.yaml}"
yq -r '.[].test' "${unsupported_file}" > "${work}/entries"
while IFS= read -r test_name; do
    crate="${test_name%%::*}"
    if ! grep -qxF -- "${crate}" "${work}/crates"; then
        echo "error: unsupported.yaml: unknown crate ${crate} in ${test_name}" >&2
        exit 1
    fi
done < "${work}/entries"

# Accept tmachine rows of every family and the host lanes.
known="$(yq '.jobs.select.steps[] | select(.id == "rows") | .run' "${root}/.github/workflows/e2e-suites.yml" \
    | sed -n "/rows='\[/,/^ *\]'/p" | sed "1s/.*rows='//; \$s/'.*//" \
    | yq '.[] | .environment + "/" + .installer')
docker
podman
kubernetes
vm"
yq -r '.[].environments[]' "${unsupported_file}" | sort -u > "${work}/environments"
while IFS= read -r environment; do
    if ! grep -qxF -- "${environment}" <<< "${known}"; then
        echo "error: unsupported.yaml: unknown environment ${environment}; use a row of e2e-suites.yml (<environment>/<installer>), docker, podman, kubernetes or vm" >&2
        exit 1
    fi
    unsupported="$("${root}/tasks/scripts/suite-unsupported.sh" "${environment}")"
    # Each harness validates its own entries (test names, issue URLs and duplicates).
    for manifest in "${manifests[@]}"; do
        OPENSHELL_TEST_UNSUPPORTED="${unsupported}" \
            cargo nextest list --locked --workspace --manifest-path "${manifest}" > /dev/null
    done
done < "${work}/environments"
