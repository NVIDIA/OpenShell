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
manifests=("${suites}/features/Cargo.toml" "${suites}"/drivers/*/Cargo.toml)
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Cargo metadata includes auto-discovered integration targets, but not their
# harness settings. Check the manifest for the explicit opt-out.
# The conformance binary registers tests from its library, not its own crate.
printf '%s\n' conformance > "${work}/crates"
for manifest in "${manifests[@]}"; do
    # shellcheck disable=SC2016 # $manifest inside the yq expression is a yq variable.
    cargo metadata --locked --no-deps --format-version 1 --manifest-path "${manifest}" \
        | yq -p=json -r '.packages[] | select(.dependencies[] | .name == "openshell-testkit")
            | .manifest_path as $manifest | .targets[]
            | select(.test and .kind[0] == "test")
            | [$manifest, .name] | @tsv' > "${work}/targets"
    while IFS=$'\t' read -r package target; do
        harnessless="$(target_name="${target}" yq -p=toml -o=yaml -r \
            '.test[] | select(.name == strenv(target_name) and .harness == false) | .name' "${package}")"
        if [[ -z "${harnessless}" ]]; then
            echo "error: ${package}: ${target} needs an explicit [[test]] with harness = false" >&2
            exit 1
        fi
        printf '%s\n' "${target//-/_}" >> "${work}/crates"
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
    | yq -o=json -I=0 'map(.environment + "/" + .installer) + ["docker", "podman", "kubernetes", "vm"]')"
# shellcheck disable=SC2016 # $name is a yq variable.
unknown="$(known="${known}" yq -r '[.[].environments[]] | unique | .[]
    | select(. as $name | env(known) | any_c(. == $name) | not)' "${unsupported_file}")"
if [[ -n "${unknown}" ]]; then
    echo "error: unsupported.yaml: unknown environment(s): ${unknown}" >&2
    exit 1
fi

# shellcheck disable=SC2016 # $name is a yq variable.
duplicates="$(yq -r '[.[] | .test as $name | .environments[] | ([$name, .] | @tsv)]
    | group_by(.) | .[] | select(length > 1) | .[0]' "${unsupported_file}")"
if [[ -n "${duplicates}" ]]; then
    echo "error: unsupported.yaml: test listed twice for the same environment (test, environment): ${duplicates}" >&2
    exit 1
fi

# A test can have different issues in different environments. Check every URL
# before collapsing the list to one entry per test for the harnesses.
bad_issues="$(yq -r '.[] | select((.issue | tag) != "!!str"
    or (.issue | test("^https://[^,[:space:]]+$") | not)) | .test' "${unsupported_file}")"
if [[ -n "${bad_issues}" ]]; then
    echo "error: unsupported.yaml: the issue must be an https:// URL for: ${bad_issues}" >&2
    exit 1
fi
unsupported="$(yq -r 'unique_by(.test) | .[] | .test + "=" + .issue' "${unsupported_file}" | paste -sd, -)"
# Include ignored tests so unsupported entries do not change the parity check.
OPENSHELL_TEST_UNSUPPORTED="${unsupported}" \
    cargo nextest list --locked --color never --run-ignored all --manifest-path "${conformance}" --message-format oneline \
    | awk '{print $2}' | sort > "${work}/nextest"
OPENSHELL_TEST_UNSUPPORTED="" \
    cargo run --quiet --locked --manifest-path "${conformance}" --bin openshell-conformance -- list \
    | awk '{print $1}' | sort > "${work}/program"
if [[ ! -s "${work}/nextest" ]] || ! diff -u "${work}/nextest" "${work}/program"; then
    echo "error: openshell-conformance and nextest must list the same nonempty set of tests" >&2
    exit 1
fi
echo "openshell-conformance lists the same $(wc -l < "${work}/program" | tr -d ' ') tests as nextest"

# Check the same inventory from a renamed prebuilt binary without Cargo on PATH.
messages="$(cargo build --locked --manifest-path "${conformance}" --bin openshell-conformance --message-format json)"
program="$(jq -r 'select(.reason == "compiler-artifact" and .executable != null) | .executable' <<< "${messages}")"
cp "${program}" "${work}/test-program"
"${work}/test-program" nextest-metadata "${work}/metadata"
nextest="$(command -v cargo-nextest)"
(
    cd "${work}/metadata"
    PATH=/usr/bin:/bin OPENSHELL_TEST_UNSUPPORTED="${unsupported}" \
        "${nextest}" nextest list --color never --run-ignored all \
        --cargo-metadata cargo-metadata.json --binaries-metadata binaries-metadata.json \
        --message-format oneline
) > "${work}/prebuilt"
grep -q '^conformance::bin/openshell-conformance ' "${work}/prebuilt"
awk '{print $2}' "${work}/prebuilt" | sort | diff -u "${work}/program" -

if [[ -n "${unsupported}" ]]; then
    for manifest in "${manifests[@]}"; do
        OPENSHELL_TEST_UNSUPPORTED="${unsupported}" \
            cargo nextest list --locked --workspace --manifest-path "${manifest}" > /dev/null
    done
fi
