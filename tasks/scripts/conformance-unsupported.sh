#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Print the tests tests/suites/conformance/unsupported.yaml lists for one
# environment as OPENSHELL_TEST_UNSUPPORTED's value (<test>=<issue>,...), or
# nothing if it has none. An environment is a tmachine row
# (<environment>/<installer>) or a host lane (docker, podman, kubernetes, vm).
# Needs mikefarah yq.

set -euo pipefail

file="${OPENSHELL_UNSUPPORTED_FILE:-$(dirname "${BASH_SOURCE[0]}")/../../tests/suites/conformance/unsupported.yaml}"

env_name="$1" yq -r '.[] | select(.environments[] == strenv(env_name)) | .test + "=" + .issue' "${file}" | paste -sd, -
