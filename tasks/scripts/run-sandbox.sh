#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

TTY_FLAG=""
if [ -t 0 ]; then
  TTY_FLAG="-it"
fi

CMD=(${usage_command:-/bin/bash})
ENV_FLAGS=""
for var in ${usage_env:-}; do
  if [ -n "${!var+x}" ]; then
    ENV_FLAGS="${ENV_FLAGS} -e ${var}=${!var}"
  else
    echo "Warning: ${var} is not set in your environment, skipping" >&2
  fi
done

docker run ${TTY_FLAG} \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  -v ${PWD}/dev-sandbox-policy.rego:/var/navigator/policy.rego:ro \
  -v ${PWD}/dev-sandbox-policy.yaml:/var/navigator/data.yaml:ro \
  -v ${PWD}/inference-routes.yaml:/var/navigator/inference-routes.yaml:ro \
  -v ${PWD}/tmp:/sandbox/tmp \
  -e HOME=/sandbox \
  -w /sandbox \
  -e NEMOCLAW_POLICY_RULES=/var/navigator/policy.rego \
  -e NEMOCLAW_POLICY_DATA=/var/navigator/data.yaml \
  -e NEMOCLAW_INFERENCE_ROUTES=/var/navigator/inference-routes.yaml \
  -e NVIDIA_API_KEY="${NVIDIA_API_KEY:-}" \
  ${ENV_FLAGS} \
  navigator/sandbox:${IMAGE_TAG:-dev} -i -- ${CMD[@]}
