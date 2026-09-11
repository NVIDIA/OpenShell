#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SDK="${1:?Usage: sdk_build_check.sh <sdk> <step1=task1> [step2=task2] ...}"
shift

PAIRS=("$@")
LOG_FILE=$(mktemp)
trap 'rm -f "$LOG_FILE"' EXIT

FAILED_STEP=""
for pair in "${PAIRS[@]}"; do
  STEP="${pair%%=*}"
  TASK="${pair#*=}"

  if ! mise run "$TASK" >> "$LOG_FILE" 2>&1; then
    FAILED_STEP="$STEP"
    break
  fi
done

LOG_CONTENT=$(tail -500 "$LOG_FILE")

if [ -z "$FAILED_STEP" ]; then
  jq -n -c --arg sdk "$SDK" \
    '{sdk: $sdk, success: true, failed_step: null, log: ""}'
else
  jq -n -c --arg sdk "$SDK" --arg step "$FAILED_STEP" --arg log "$LOG_CONTENT" \
    '{sdk: $sdk, success: false, failed_step: $step, log: $log}'
  exit 1
fi
