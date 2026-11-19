#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Read tests/suites/conformance/unsupported.yaml.
#
#   conformance-unsupported.sh <environment>   print the entries for one
#       environment as OPENSHELL_TEST_UNSUPPORTED's value (<test>=<issue>,...);
#       prints nothing if it has none. An environment is a tmachine row
#       (<environment>/<installer>) or a host lane (docker, podman,
#       kubernetes, vm).
#   conformance-unsupported.sh --check         validate the file
#   conformance-unsupported.sh --tests         print each listed test's name as
#       `openshell-conformance list` shows it

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
file="${OPENSHELL_UNSUPPORTED_FILE:-${root}/tests/suites/conformance/unsupported.yaml}"

fail() {
    echo "error: ${file#"${root}/"}: $*" >&2
    exit 1
}

yq --version 2>/dev/null | grep -q mikefarah || fail "mikefarah yq (https://github.com/mikefarah/yq) is required"
command -v jq >/dev/null || fail "jq is required"
entries="$(yq --output-format json '. // []' "${file}")" || fail "not valid YAML"

check() {
    jq -r '
        if type != "array" then "must be a list of entries"
        else
            (to_entries[] | .key as $i | .value as $e
             | if ($e | type) != "object" then "entry \($i + 1) must be a mapping"
               elif (($e.test // "") | type) != "string" or (($e.test // "") == "") then "entry \($i + 1): test must be a name like conformance::<module>::<name>"
               elif (($e.issue // "") | type) != "string" or (($e.issue // "") | test("^https://.+") | not) then "entry \($i + 1) (\($e.test)): issue must be an https:// URL"
               elif (($e.environments // []) | type) != "array" or (($e.environments // []) | length == 0) or (($e.environments | map(type == "string" and test("^[^,[:space:]]+$")) | all) | not) then "entry \($i + 1) (\($e.test)): environments must be a non-empty list of names without commas or spaces"
               else empty end),
            ([.[] | .test as $t | .environments[]? | "\($t) on \(.)"] | group_by(.) | map(select(length > 1) | "\(.[0]) is listed twice") | .[])
        end' <<< "${entries}"
}

# The names an entry may use: the conformance rows of e2e-suites.yml, which
# the tmachine job looks up as <environment>/<installer>, and the host lanes.
environment_names() {
    local workflow="${root}/.github/workflows/e2e-suites.yml"
    yq '.jobs.select.steps[] | select(.id == "rows") | .run' "${workflow}" \
        | sed -n "/rows='\[/,/^ *\]'/p" | sed "1s/.*rows='//; \$s/'.*//" \
        | jq -r '.[] | select(.family == "conformance") | "\(.environment)/\(.installer)"'
    printf '%s\n' docker podman kubernetes vm
}

unknown_environments() {
    local known
    known="$(environment_names)"
    [[ -n "${known}" ]] || { echo "could not read the environments from e2e-suites.yml"; return; }
    jq -r --arg known "${known}" '($known | split("\n")) as $names
        | .[] | .test as $t | .environments[]? | select(. as $e | $names | index($e) | not)
        | "\($t): unknown environment \(.); use a conformance row of e2e-suites.yml (<environment>/<installer>) or docker, podman, kubernetes, vm"' <<< "${entries}"
}

case "${1:-}" in
    --check)
        problems="$(check)"
        [[ -n "${problems}" ]] || problems="$(unknown_environments)"
        if [[ -n "${problems}" ]]; then
            while IFS= read -r problem; do
                echo "error: ${file#"${root}/"}: ${problem}" >&2
            done <<< "${problems}"
            exit 1
        fi
        ;;
    --tests)
        jq -r '.[].test | ltrimstr("conformance::")' <<< "${entries}" | sort -u
        ;;
    "" | -*)
        echo "usage: $0 <environment> | --check | --tests" >&2
        exit 2
        ;;
    *)
        problems="$(check)"
        [[ -z "${problems}" ]] || fail "${problems%%$'\n'*} (run with --check)"
        jq -r --arg env "$1" '[.[] | select(.environments | index($env)) | "\(.test)=\(.issue)"] | join(",")' <<< "${entries}"
        ;;
esac
