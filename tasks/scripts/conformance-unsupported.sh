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

command -v yq >/dev/null || fail "yq is required"
command -v jq >/dev/null || fail "jq is required"
entries="$(yq --output-format json '. // []' "${file}")" || fail "not valid YAML"

check() {
    jq -r '
        if type != "array" then "must be a list of entries"
        else
            (to_entries[] | .key as $i | .value as $e
             | if ($e | type) != "object" then "entry \($i + 1) must be a mapping"
               elif (($e.test // "") | type) != "string" or (($e.test // "") | startswith("conformance::") | not) then "entry \($i + 1): test must be a string starting with conformance::"
               elif (($e.issue // "") | type) != "string" or (($e.issue // "") | test("^https://.+") | not) then "entry \($i + 1) (\($e.test)): issue must be an https:// URL"
               elif (($e.environments // []) | type) != "array" or (($e.environments // []) | length == 0) or (($e.environments | map(type == "string" and test("^[^,[:space:]]+$")) | all) | not) then "entry \($i + 1) (\($e.test)): environments must be a non-empty list of names without commas or spaces"
               else empty end),
            ([.[] | .test as $t | .environments[]? | "\($t) on \(.)"] | group_by(.) | map(select(length > 1) | "\(.[0]) is listed twice") | .[])
        end' <<< "${entries}"
}

case "${1:-}" in
    --check)
        problems="$(check)"
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
