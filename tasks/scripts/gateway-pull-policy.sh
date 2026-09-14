#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Normalize compatibility inputs at the development-script boundary while
# keeping schema-v2 TOML and backend validation strict.
normalize_image_pull_policy() {
  local value
  value="$(printf '%s' "${1:-}" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    always)
      printf '%s\n' "always"
      ;;
    if_not_present|ifnotpresent|missing)
      printf '%s\n' "if_not_present"
      ;;
    never)
      printf '%s\n' "never"
      ;;
    newer)
      printf '%s\n' "newer"
      ;;
    *)
      printf 'unsupported image pull policy: %s\n' "${1:-}" >&2
      return 2
      ;;
  esac
}
