#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shell helpers shared by local gateway launch scripts. This file is sourced,
# rather than executed, so helpers must not change shell options or process
# environment at import time.

# Escape a value for a TOML basic string. This supports operator-provided paths
# and URLs without allowing a quote or control character to add TOML fields.
toml_escape() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "${value}"
}

# Append OTLP export to a gateway config when OPENSHELL_DEV_OTLP_ENDPOINT is
# set. Export stays off otherwise so no collector is assumed.
append_dev_otlp_config() {
  local config_path=$1
  local endpoint=${OPENSHELL_DEV_OTLP_ENDPOINT:-}
  if [[ -z "${endpoint}" ]]; then
    echo "OTLP export disabled; set OPENSHELL_DEV_OTLP_ENDPOINT to enable it."
    return
  fi

  cat >>"${config_path}" <<TOML

[openshell.gateway.otlp]
endpoint = "$(toml_escape "${endpoint}")"

[openshell.gateway.otlp.ocsf]
enabled = true

[openshell.gateway.otlp.agent]
enabled = true
TOML
  echo "OTLP trace export, OCSF log export, and the agent trace relay enabled for ${endpoint}."
}
